package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/ipfs/go-cid"
	"github.com/minio/blake2b-simd"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/chain/types"
	lcli "github.com/filecoin-project/lotus/cli"

	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	iact "github.com/filecoin-project/specs-actors/actors/builtin/init"
	msig "github.com/filecoin-project/specs-actors/actors/builtin/multisig"
)

const blocksInADay = (24 * 60 * 60) / 30
const blocksInAMonth = (blocksInADay * 365) / 12

type CreateParams struct {
	Name          string
	Entity        string
	Hash          string
	Amount        string
	VestingMonths int
	Custodian     string
	MultisigM     int
	MultisigN     int
	Addresses     []address.Address
}

func jobStr(job *MsigCreationProgress) string {
	return fmt.Sprintf("%s %s %s", job.Params.Name, job.Params.Custodian, job.Params.Entity)
}

type MsigCreationProgress struct {
	Params    CreateParams
	CreateCID cid.Cid
	ActorID   address.Address

	SetVestingCID cid.Cid
	FundsLocked   bool

	SetThresholdCID cid.Cid
	ThresholdSet    bool

	RemoveControlCID cid.Cid
	ControlChanged   bool

	Complete bool

	SentFunds cid.Cid

	AdminRemovals map[string]cid.Cid
}

type MsigCreationData struct {
	Jobs              []*MsigCreationProgress
	Creator           address.Address
	AdminAux          []address.Address
	SkipRemove        bool // TODO: deleteme
	VestingStartEpoch abi.ChainEpoch
}

var createMsigsCmd = &cli.Command{
	Name: "create-msigs",
	Subcommands: []*cli.Command{
		msigCreateStartCmd,
		msigCreateCheckCreationCmd,
		msigCreateSetVestingCmd,
		msigCreateNextCmd,
		msigCreateVerifyCmd,
		msigCreateFillCmd,
		msigCreateAuditsCmd,
		msigCreateOutputCsvCmd,
		msigCreateRemoveAdminsCmd,
	},
}

var msigCreateStartCmd = &cli.Command{
	Name:        "start",
	Description: "start of multisig accounts creation, parses initial csv input and sends creation messages for each, recording the message cid in the output file",
	Flags: []cli.Flag{
		&cli.Int64Flag{
			Name:  "vesting-start",
			Usage: "epoch at which vesting will start for the created wallets",
		},
		&cli.StringFlag{
			Name:  "creator",
			Usage: "address to use as the creator and controller for the entire setup process",
		},
		&cli.StringFlag{
			Name:  "admin-aux",
			Usage: "additional admin keys for setting up wallets with",
		},
		&cli.BoolFlag{
			Name:  "skip-remove",
			Usage: "set to skip removal of initial control address during setup flow",
		},
		&cli.BoolFlag{
			Name:  "only-admin-keys",
			Usage: "only insert admin keys during initial creation",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		var createAddr address.Address
		if ca := cctx.String("creator"); ca != "" {
			caddr, err := address.NewFromString(ca)
			if err != nil {
				return err
			}
			createAddr = caddr
		} else {
			return fmt.Errorf("must specify creator address through flag")
		}

		var adminAux []address.Address
		if aastr := cctx.String("admin-aux"); aastr != "" {
			for _, a := range strings.Split(aastr, ",") {
				auxAddr, err := address.NewFromString(a)
				if err != nil {
					return fmt.Errorf("failed to parse aux address: %w", err)
				}
				adminAux = append(adminAux, auxAddr)
			}
		}

		params, err := parseCreateParams(cctx.Args().First())
		if err != nil {
			return err
		}

		cd := &MsigCreationData{
			Creator:           createAddr,
			AdminAux:          adminAux,
			VestingStartEpoch: abi.ChainEpoch(cctx.Int64("vesting-start")),
		}

		seenHashes := make(map[string]bool)
		for _, p := range params {
			if seenHashes[p.Hash] {
				return fmt.Errorf("duplicate account in input: %s", p.Hash)
			}
			seenHashes[p.Hash] = true
		}

		for _, p := range params {
			controls := []address.Address{createAddr}

			if len(adminAux) > 0 {
				controls = append(controls, adminAux...)
			}

			if !cctx.Bool("only-admin-keys") {
				controls = append(controls, p.Addresses...)
			}

			createCid, err := api.MsigCreate(ctx, uint64(1+len(adminAux)), controls, 0, types.NewInt(0), createAddr, types.NewInt(0))
			if err != nil {
				return xerrors.Errorf("failed to create multisigs: %w", err)
			}

			cd.Jobs = append(cd.Jobs, &MsigCreationProgress{
				Params:    p,
				CreateCID: createCid,
			})
		}

		fi, err := os.Create("msig-creation-progress.json")
		if err != nil {
			return err
		}
		defer fi.Close()

		if err := json.NewEncoder(fi).Encode(cd); err != nil {
			return err
		}

		return nil
	},
}

func parseCreateParams(fname string) ([]CreateParams, error) {
	fi, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	records, err := csv.NewReader(fi).ReadAll()
	if err != nil {
		return nil, err
	}

	fmt.Println(records[0])

	var out []CreateParams
	for i, r := range records[1:] {
		if len(r) < 9 {
			return nil, fmt.Errorf("records on row %d were invalid", i)
		}

		amt, err := types.ParseFIL(r[3])
		if err != nil {
			return nil, fmt.Errorf("failed to parse value field of row %d: %w", i, err)
		}

		vmonths, err := strconv.Atoi(r[4])
		if err != nil {
			return nil, fmt.Errorf("failed to parse vesting months field of row %d: %w", i, err)
		}

		msigM, err := strconv.Atoi(r[5])
		if err != nil {
			return nil, fmt.Errorf("failed to parse msigM field of row %d: %w", i, err)
		}

		msigN, err := strconv.Atoi(r[6])
		if err != nil {
			return nil, fmt.Errorf("failed to parse msigN field of row %d: %w", i, err)
		}

		var addresses []address.Address
		for j, a := range strings.Split(r[7], ":") {
			addr, err := address.NewFromString(a)
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %d on row %d: %w", j, i, err)
			}
			addresses = append(addresses, addr)
		}
		if len(addresses) != msigN {
			return nil, fmt.Errorf("length of addresses set in row %d does not match multisig N field", i)
		}

		p := CreateParams{
			Name:          r[0],
			Entity:        r[1],
			Hash:          r[2],
			Amount:        amt.String(),
			VestingMonths: vmonths,
			Custodian:     r[5],
			MultisigM:     msigM,
			MultisigN:     msigN,
			Addresses:     addresses,
		}

		out = append(out, p)
	}
	return out, nil
}

var msigCreateCheckCreationCmd = &cli.Command{
	Name:        "check-creation",
	Description: "checks that the creations kicked off in 'start' were successful and records the results",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		var complete int
		for _, job := range msd.Jobs {
			if job.ActorID != address.Undef {
				complete++
				continue
			}

			fmt.Println("finding creation receipt for ", job.Params.Name)
			r, err := api.StateGetReceipt(ctx, job.CreateCID, types.EmptyTSK)
			if err != nil {
				log.Warnf("no receipt found for %s", job.CreateCID)
			} else {
				if r != nil {
					if r.ExitCode != 0 {
						fmt.Printf("creation job failed for %s %s %s: %d\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, r.ExitCode)
					} else {
						var er iact.ExecReturn
						if err := er.UnmarshalCBOR(bytes.NewReader(r.Return)); err != nil {
							return xerrors.Errorf("return value of create message failed to parse: %w", err)
						}

						fmt.Printf("actor create successful: %s %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, er.RobustAddress)
						job.ActorID = er.RobustAddress
						if err := writeProgress(); err != nil {
							return err
						}
						complete++
					}
				} else {
					fmt.Printf("creation message for %s hasnt made it into the chain yet\n", job.Params.Custodian)
				}
			}

		}

		fmt.Printf("%d / %d Complete.\n", complete, len(msd.Jobs))

		return nil
	},
}

var msigCreateSetVestingCmd = &cli.Command{
	Name:        "set-vesting",
	Description: "set the vesting schedule of wallets",
	Subcommands: []*cli.Command{
		msigCreateSetVestingProposeCmd,
		msigCreateSetVestingCheckCmd,
		msigCreateSetVestingApproveCmd,
	},
}

var msigCreateSetVestingProposeCmd = &cli.Command{
	Name:        "propose",
	Description: "propose the vesting schedule of wallets",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		for _, job := range msd.Jobs {
			if job.ActorID == address.Undef {
				fmt.Printf("actor creation not yet complete for %s. Please run 'check-creation'\n", jobStr(job))
				return nil
			}
		}

		for _, job := range msd.Jobs {
			famt, err := types.ParseFIL(job.Params.Amount)
			if err != nil {
				return xerrors.Errorf("failed to parse fil amount: %w", err)
			}
			params := &msig.LockBalanceParams{
				StartEpoch:     msd.VestingStartEpoch,
				UnlockDuration: abi.ChainEpoch(blocksInAMonth * job.Params.VestingMonths),
				Amount:         big.Int(famt),
			}

			lmcid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.LockBalance)
			if err != nil {
				return fmt.Errorf("failed to propose lock funds operation on %s: %w", jobStr(job), err)
			}

			job.SetVestingCID = lmcid
			if err := writeProgress(); err != nil {
				return err
			}
			fmt.Printf("proposed funds locking for %s in %s\n", job.Params.Name, lmcid)
		}

		return nil
	},
}

var msigCreateSetVestingCheckCmd = &cli.Command{
	Name:        "check",
	Description: "check that the proposals for set-vesting have landed",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		for _, job := range msd.Jobs {
			if job.SetVestingCID == cid.Undef {
				fmt.Printf("set vesting operation not yet proposed for %s. Please run 'set-vesting propose'", jobStr(job))
				return nil
			}
		}

		fmt.Printf("Hash,SetVestingCID,Applied,ActorID,TxnID,Error\n")
		for _, job := range msd.Jobs {
			pr, err := checkProposeReceipt(ctx, api, job.SetVestingCID)
			if err != nil {
				errstr := fmt.Sprintf("set vesting not complete: %s", err)
				fmt.Printf("%s,%s,false,%s,-1,%s\n", job.Params.Hash, job.SetVestingCID, job.ActorID, errstr)
				continue
			}

			if pr.Applied {
				fmt.Printf("%s,%s,true,%s,-1,\n", job.Params.Hash, job.ActorID, job.SetVestingCID)
				job.FundsLocked = true
				if err := writeProgress(); err != nil {
					return err
				}
			} else {
				if len(msd.AdminAux) > 0 {
					mstate, _, err := getMsigState(ctx, api, job.ActorID)
					if err != nil {
						return fmt.Errorf("failed to get actor state for %s: %w", job.ActorID, err)
					}

					if mstate.UnlockDuration != 0 {
						// Success!
						// Note: this is a pretty crappy metric for 'success',
						// but we have multiple auditing steps in here anyways,
						// so its good enough

						job.FundsLocked = true
						if err := writeProgress(); err != nil {
							return err
						}

						fmt.Printf("%s,%s,true,%s,%d,\n", job.Params.Hash, job.SetVestingCID, job.ActorID, pr.TxnID)
						continue
					}

					fmt.Printf("%s,%s,false,%s,%d,\n", job.Params.Hash, job.SetVestingCID, job.ActorID, pr.TxnID)
					continue
				} else {
					errstr := "funds locking for failed to apply but shouldnt have any required approvals"
					fmt.Printf("%s,%s,false,%s,-1,%s\n", job.Params.Hash, job.SetVestingCID, job.ActorID, errstr)
					continue
				}
			}

		}

		return nil
	},
}

var msigCreateSetVestingApproveCmd = &cli.Command{
	Name:        "approve",
	Description: "approve the vesting schedule of wallets",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "admin-key",
			Usage: "specify admin key to approve set vesting with",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}

		type setVestingRow struct {
			Hash          string
			SetVestingCID cid.Cid
			Applied       bool
			ActorID       address.Address
			TxnID         msig.TxnID
			Error         string
		}

		rows, err := csv.NewReader(fi).ReadAll()
		if err != nil {
			return err
		}

		var svrows []setVestingRow
		for _, r := range rows[1:] {

			svc, err := cid.Decode(r[1])
			if err != nil {
				return err
			}

			var applied bool
			if r[2] == "true" {
				applied = true
			} else if r[2] != "false" {
				return fmt.Errorf("expected column three to be 'true' or 'false'")
			}

			actId, err := address.NewFromString(r[3])
			if err != nil {
				return fmt.Errorf("failed to parse actor ID from input csv: %w", err)
			}

			txnid, err := strconv.ParseInt(r[4], 10, 64)
			if err != nil {
				return fmt.Errorf("failed to parse txnid: %w", err)
			}

			svrows = append(svrows, setVestingRow{
				Hash:          r[0],
				SetVestingCID: svc,
				Applied:       applied,
				ActorID:       actId,
				TxnID:         msig.TxnID(txnid),
				Error:         r[5],
			})
		}

		adminKey, err := address.NewFromString(cctx.String("admin-key"))
		if err != nil {
			return fmt.Errorf("failed to parse admin-key: %w", err)
		}

		for _, svr := range svrows {
			params := &msig.TxnIDParams{
				ID: svr.TxnID,
			}

			buf := new(bytes.Buffer)
			if err := params.MarshalCBOR(buf); err != nil {
				return err
			}

			msg := &types.Message{
				To:     svr.ActorID,
				From:   adminKey,
				Method: builtin.MethodsMultisig.Approve,
				Params: buf.Bytes(),
			}

			sm, err := api.MpoolPushMessage(ctx, msg, nil)
			if err != nil {
				return fmt.Errorf("mpool push message failed: %w", err)
			}

			fmt.Printf("approved txn %d on %s in msg %s\n", svr.TxnID, svr.ActorID, sm.Cid())
		}

		return nil
	},
}

var msigCreateNextCmd = &cli.Command{
	Name:        "next",
	Description: "perform next required processing for multisig creation",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		return fmt.Errorf("this method is deprecated, i'm only keeping it around to copy bits out of it into other commands")

		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		var progress int
		for _, job := range msd.Jobs {
			if job.Complete {
				fmt.Printf("Jobs complete: %d / %d\n", progress, len(msd.Jobs))
				progress++
				continue
			}
			if job.ActorID == address.Undef {
				fmt.Println("finding creation receipt for ", job.Params.Name)
				r, err := api.StateGetReceipt(ctx, job.CreateCID, types.EmptyTSK)
				if err != nil {
					log.Warnf("no receipt found for %s", job.CreateCID)
				} else {
					if r != nil {
						if r.ExitCode != 0 {
							fmt.Printf("creation job failed for %s %s %s: %d\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, r.ExitCode)
						} else {
							var er iact.ExecReturn
							if err := er.UnmarshalCBOR(bytes.NewReader(r.Return)); err != nil {
								return xerrors.Errorf("return value of create message failed to parse: %w", err)
							}

							fmt.Printf("actor create successful: %s %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, er.RobustAddress)
							job.ActorID = er.RobustAddress
							if err := writeProgress(); err != nil {
								return err
							}
						}
					} else {
						fmt.Printf("creation message for %s hasnt made it into the chain yet\n", job.Params.Custodian)
					}
				}
			}

			if job.ActorID != address.Undef && !job.SetVestingCID.Defined() {
				famt, err := types.ParseFIL(job.Params.Amount)
				if err != nil {
					return xerrors.Errorf("failed to parse fil amount: %w", err)
				}
				params := &msig.LockBalanceParams{
					StartEpoch:     0,
					UnlockDuration: abi.ChainEpoch(blocksInAMonth * job.Params.VestingMonths),
					Amount:         big.Int(famt),
				}

				lmcid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.LockBalance)
				if err != nil {
					return fmt.Errorf("failed to propose lock funds operation on %s: %w", jobStr(job), err)
				}

				job.SetVestingCID = lmcid
				if err := writeProgress(); err != nil {
					return err
				}
				fmt.Printf("proposed funds locking for %s in %s\n", job.Params.Name, lmcid)
			}

			if job.SetVestingCID.Defined() && !job.FundsLocked {
				fmt.Println("finding funds locking receipt for ", job.Params.Name)
				pr, err := checkProposeReceipt(ctx, api, job.SetVestingCID)
				if err != nil {
					fmt.Printf("set vesting (%s %s %s) not complete: %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
					continue
				}

				if !pr.Applied {
					fmt.Printf("set vesting (%s %s %s) not complete: %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, "transaction not applied")
					continue
				}

				fmt.Printf("funds locking successful: %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity)
				job.FundsLocked = true
				if err := writeProgress(); err != nil {
					return err
				}

			}

			if job.Params.MultisigM == 1 && !job.ThresholdSet {
				job.ThresholdSet = true
				fmt.Printf("no need to change threshold for %s, already 1\n", job.Params.Name)
				if err := writeProgress(); err != nil {
					return err
				}
			}

			act, err := api.StateGetActor(ctx, job.ActorID, types.EmptyTSK)
			if err != nil {
				fmt.Printf("could not get actor on chain for %s: %s", job.ActorID, err)
				continue
			}
			reqamt, err := types.ParseFIL(job.Params.Amount)
			if err != nil {
				return fmt.Errorf("failed to parse amount in job %s: %w", jobStr(job), err)
			}

			if types.BigCmp(act.Balance, types.BigInt(reqamt)) < 0 {
				fmt.Printf("Need to send funds to %s: Balance %s < %s\n", jobStr(job), act.Balance, reqamt)
				continue
			}

			if job.FundsLocked && job.Params.MultisigM != 1 && !job.SetThresholdCID.Defined() {
				params := &msig.ChangeNumApprovalsThresholdParams{
					NewThreshold: uint64(job.Params.MultisigM),
				}

				mcid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.ChangeNumApprovalsThreshold)
				if err != nil {
					return fmt.Errorf("failed to propose approval threshold change for %s %s %s: %w", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
				}

				job.SetThresholdCID = mcid
				if err := writeProgress(); err != nil {
					return err
				}
			}

			if job.SetThresholdCID.Defined() && !job.ThresholdSet {
				fmt.Println("finding set threshold receipt for ", job.Params.Name)
				pr, err := checkProposeReceipt(ctx, api, job.SetThresholdCID)
				if err != nil {
					fmt.Printf("set threshold (%s %s %s) not complete: %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
					continue
				}

				if !pr.Applied {
					fmt.Printf("set threshold (%s %s %s) not complete: %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, "transaction not applied")
					continue
				}

				fmt.Printf("set threshold successful: %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity)
				job.ThresholdSet = true
				if err := writeProgress(); err != nil {
					return err
				}
			}

			if job.ThresholdSet && !job.RemoveControlCID.Defined() && !msd.SkipRemove {
				params := &msig.RemoveSignerParams{
					Signer: msd.Creator,
				}

				fmt.Println("Proposing removal of control address on ", job.ActorID)
				mcid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.RemoveSigner)
				if err != nil {
					return fmt.Errorf("failed to propose remove signer for %s %s %s: %w", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
				}

				job.RemoveControlCID = mcid
				if err := writeProgress(); err != nil {
					return err
				}
			}

			if !job.ControlChanged && job.RemoveControlCID.Defined() {
				if job.Params.MultisigM == 1 {
					fmt.Println("finding remove control address message for ", job.Params.Name)
					pr, err := checkProposeReceipt(ctx, api, job.RemoveControlCID)
					if err != nil {
						fmt.Println("removing control address not complete")
						continue
					}

					if !pr.Applied {
						fmt.Println("removing control address not complete")
						continue
					}

					fmt.Println("proposal of address removal complete")
				}
				job.ControlChanged = true // eh, close enough
				if err := writeProgress(); err != nil {
					return err
				}
			}

			if job.ControlChanged || msd.SkipRemove {
				// nothing else to do, this ones complete
				progress++
				job.Complete = true
				if err := writeProgress(); err != nil {
					return err
				}
			}
		}
		fmt.Printf("%d / %d Jobs complete\n", progress, len(msd.Jobs))

		return nil
	},
}

func checkProposeReceipt(ctx context.Context, api api.FullNode, c cid.Cid) (*msig.ProposeReturn, error) {
	r, err := api.StateGetReceipt(ctx, c, types.EmptyTSK)
	if err != nil {
		return nil, fmt.Errorf("finding receipt failed: %w", err)
	}

	if r == nil {
		return nil, fmt.Errorf("message hasnt made it into the chain yet")
	}

	if r.ExitCode != 0 {
		return nil, fmt.Errorf("propose receipt had nonzero exitcode: %d", r.ExitCode)
	}

	var pr msig.ProposeReturn
	if err := pr.UnmarshalCBOR(bytes.NewReader(r.Return)); err != nil {
		return nil, xerrors.Errorf("return value of %s failed to parse: %w", c, err)
	}

	if pr.Code != 0 {
		return nil, fmt.Errorf("multisig operation failed: %d", pr.Code)
	}

	return &pr, nil
}

type cborMarshaler interface {
	MarshalCBOR(io.Writer) error
}

func msigPropose(ctx context.Context, api api.FullNode, sender address.Address, act address.Address, params cborMarshaler, method abi.MethodNum) (cid.Cid, error) {
	buf := new(bytes.Buffer)
	if err := params.MarshalCBOR(buf); err != nil {
		return cid.Undef, fmt.Errorf("failed to marshal parameters: %w", err)
	}

	addr, err := api.StateLookupID(ctx, act, types.EmptyTSK)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to look up actor ID for %s: %s", act, err)
	}

	prop := msig.ProposeParams{
		To:     addr,
		Value:  abi.NewTokenAmount(0),
		Method: method,
		Params: buf.Bytes(),
	}

	buf2 := new(bytes.Buffer)
	if err := prop.MarshalCBOR(buf2); err != nil {
		return cid.Undef, err
	}

	msg := &types.Message{
		From:   sender,
		To:     addr,
		Method: builtin.MethodsMultisig.Propose,
		Params: buf2.Bytes(),
	}

	sm, err := api.MpoolPushMessage(ctx, msg, nil)
	if err != nil {
		return cid.Undef, fmt.Errorf("failed to push message: %w", err)
	}

	return sm.Cid(), nil

}

var msigCreateVerifyCmd = &cli.Command{
	Name:        "verify",
	Description: "verify wallets were properly setup",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		curTs, err := api.ChainHead(ctx)
		if err != nil {
			return err
		}

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		for _, job := range msd.Jobs {
			if !job.Complete {
				fmt.Printf("%s not complete\n", jobStr(job))
			} else {
				act, err := api.StateGetActor(ctx, job.ActorID, types.EmptyTSK)
				if err != nil {
					return fmt.Errorf("failed to get actor: %w", err)
				}
				fmt.Printf("Wallet: %s - %s\n", jobStr(job), job.ActorID)

				addr, err := api.StateLookupID(ctx, job.ActorID, types.EmptyTSK)
				if err != nil {
					return err
				}

				fmt.Printf("\tID: %s\n", addr)

				amt, err := types.ParseFIL(job.Params.Amount)
				if err != nil {
					return fmt.Errorf("failed to parse amount in job create params: %w", err)
				}

				balanceGood := act.Balance.Equals(big.Int(amt))
				extra := ""
				if !balanceGood {
					extra = fmt.Sprintf("\t(should be %s)", amt)
				}
				goodbad(balanceGood, "\tBalance: %s%s\n", types.FIL(act.Balance), extra)

				if act.Code != builtin.MultisigActorCodeID {
					fmt.Println("NOT A MULTISIG!!")
					continue
				}

				data, err := api.ChainReadObj(ctx, act.Head)
				if err != nil {
					return fmt.Errorf("failed to read state: %w", err)
				}

				var msigst msig.State
				if err := msigst.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
					return err
				}

				addrsCorrect := addressesAreSame(job.Params.Addresses, msigst.Signers)
				goodbad(addrsCorrect, "\t%s\n", msigst.Signers)

				expDuration := abi.ChainEpoch(blocksInAMonth * job.Params.VestingMonths)
				durGood := msigst.UnlockDuration == expDuration
				goodbad(durGood, "\tVesting Duration: %d (%d months)\n", msigst.UnlockDuration, msigst.UnlockDuration/blocksInAMonth)
				expSpendable := types.FIL(types.BigSub(big.Int(amt), msigst.AmountLocked(curTs.Height())))
				elapsedPerc := 100 * float64(curTs.Height()-msigst.StartEpoch) / float64(msigst.UnlockDuration)
				fmt.Printf("\tSpendable: (%0.1f) %s (exp: %s)\n", elapsedPerc, types.FIL(types.BigSub(act.Balance, msigst.AmountLocked(curTs.Height()))), expSpendable)

				fmt.Println()
			}
		}

		return nil
	},
}

func goodbad(good bool, format string, args ...interface{}) {
	if good {
		color.Green(format, args...)
	} else {
		color.Red(format, args...)
	}
}

func addressesAreSame(s1, s2 []address.Address) bool {
	sort.Slice(s1, func(i, j int) bool {
		return s1[i].String() < s1[j].String()
	})

	sort.Slice(s2, func(i, j int) bool {
		return s2[i].String() < s2[j].String()
	})

	if len(s1) != len(s2) {
		return false
	}

	for i := 0; i < len(s1); i++ {
		if s1[i] != s2[i] {
			return false
		}
	}

	return true
}

var msigCreateFillCmd = &cli.Command{
	Name:        "fill",
	Description: "fill wallets with appropriate funds from source funding pool",
	Subcommands: []*cli.Command{
		msigCreateFillProposeCmd,
		msigCreateFillApproveCmd,
	},
}

var msigCreateFillProposeCmd = &cli.Command{
	Name:        "propose",
	Description: "propose transactions to fill wallets with appropriate funds from source funding pool",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "source",
			Usage: "source account to pull funds from",
		},
		&cli.StringFlag{
			Name:  "signer",
			Usage: "address of signer for the 'source' multisig",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		sourceAddr, err := address.NewFromString(cctx.String("source"))
		if err != nil {
			return fmt.Errorf("failed to parse 'source' address: %w", err)
		}

		signerAddr, err := address.NewFromString(cctx.String("signer"))
		if err != nil {
			return fmt.Errorf("failed to parse 'signer' address: %w", err)
		}

		for _, job := range msd.Jobs {
			if !job.FundsLocked {
				return fmt.Errorf("vesting schedule not set for all wallets yet, please set vesting before sending funds")
			}
		}

		for _, job := range msd.Jobs {
			addr, err := api.StateLookupID(ctx, job.ActorID, types.EmptyTSK)
			if err != nil {
				return fmt.Errorf("failed to lookup ID: %w", err)
			}

			fmt.Printf("Wallet %s - %s\n", jobStr(job), addr)
			targetAmt, err := types.ParseFIL(job.Params.Amount)
			if err != nil {
				return fmt.Errorf("failed to parse amount param: %w", err)
			}

			act, err := api.StateGetActor(ctx, addr, types.EmptyTSK)
			if err != nil {
				return fmt.Errorf("failed to find actor: %w", err)
			}

			fmt.Printf("\tCurrent balance: %s\n", types.FIL(act.Balance))
			fmt.Printf("\tTarget balance: %s\n", targetAmt)

			toSend := types.BigSub(big.Int(targetAmt), act.Balance)
			if toSend.Sign() <= 0 {
				fmt.Printf("Balance is sufficient, continuing...\n\n")
				continue
			}

			fmt.Printf("\n\tAbout to send %s to %s (%s)\n", types.FIL(toSend), addr, job.ActorID)

			if job.SentFunds.Defined() {
				fmt.Println("funds already sent to target account: ", job.SentFunds)
				continue
			}

			params := &msig.ProposeParams{
				To:    job.ActorID,
				Value: toSend,
			}

			buf := new(bytes.Buffer)
			if err := params.MarshalCBOR(buf); err != nil {
				return err
			}

			msg := &types.Message{
				From:   signerAddr,
				To:     sourceAddr,
				Method: builtin.MethodsMultisig.Propose,
				Params: buf.Bytes(),
			}

			sm, err := api.MpoolPushMessage(ctx, msg, nil)
			if err != nil {
				return fmt.Errorf("failed to push message: %w", err)
			}

			job.SentFunds = sm.Cid()
			if err := writeProgress(); err != nil {
				return fmt.Errorf("failed to write progress after sending funds: %w", err)
			}
		}
		return nil
	},
}

type approvalInfo struct {
	TxnID    int
	To       address.Address
	Proposer address.Address
	Value    abi.TokenAmount
}

var msigCreateFillApproveCmd = &cli.Command{
	Name:        "approve",
	Description: "approve transactions to fill wallets with appropriate funds from source funding pool",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "source",
			Usage: "source account to pull funds from",
		},
		&cli.StringFlag{
			Name:  "signer",
			Usage: "address of signer for the 'source' multisig",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}

		lines, err := csv.NewReader(fi).ReadAll()
		if err != nil {
			return fmt.Errorf("failed to read tx audit file: %w", err)
		}

		var toApprove []approvalInfo
		for i, l := range lines[1:] {
			v, err := strconv.Atoi(l[5])
			if err != nil {
				return fmt.Errorf("failed to parse txn id on row %d: %w", i, err)
			}
			proposer, err := address.NewFromString(l[4])
			if err != nil {
				return fmt.Errorf("failed to parse proposer from input row %d: %w", i, err)
			}

			amount, err := types.ParseFIL(l[6])
			if err != nil {
				return fmt.Errorf("failed to parse amount from input row %d: %w", i, err)
			}
			target, err := address.NewFromString(l[1])
			if err != nil {
				return fmt.Errorf("failed to parse multisig address on row %d: %w", i, err)
			}

			idaddr, err := api.StateLookupID(ctx, target, types.EmptyTSK)
			if err != nil {
				return err
			}

			toApprove = append(toApprove, approvalInfo{
				TxnID:    v,
				To:       idaddr,
				Proposer: proposer,
				Value:    big.Int(amount),
			})
		}
		fi.Close()

		sourceAddr, err := address.NewFromString(cctx.String("source"))
		if err != nil {
			return fmt.Errorf("failed to parse 'source' address: %w", err)
		}

		signerAddr, err := address.NewFromString(cctx.String("signer"))
		if err != nil {
			return fmt.Errorf("failed to parse 'signer' address: %w", err)
		}

		for _, txn := range toApprove {
			phash, err := msig.ComputeProposalHash(&msig.Transaction{
				To:       txn.To,
				Value:    txn.Value,
				Approved: []address.Address{txn.Proposer},
			}, blake2b.Sum256)
			if err != nil {
				return fmt.Errorf("failed to compute proposal hash: %w", err)
			}

			_ = phash
			// TODO: figure out exactly how the proposal hash stuff works
			params := &msig.TxnIDParams{
				ID: msig.TxnID(txn.TxnID),
				//ProposalHash: phash,
			}

			buf := new(bytes.Buffer)
			if err := params.MarshalCBOR(buf); err != nil {
				return err
			}

			msg := &types.Message{
				To:     sourceAddr,
				From:   signerAddr,
				Method: builtin.MethodsMultisig.Approve,
				Params: buf.Bytes(),
			}

			sm, err := api.MpoolPushMessage(ctx, msg, nil)
			if err != nil {
				return err
			}

			fmt.Printf("Approval for txn %d sent in %s\n", txn.TxnID, sm.Cid())
		}

		return nil
	},
}

var msigCreateAuditsCmd = &cli.Command{
	Name:        "audit",
	Description: "a collection of commands for auditing the process",
	Subcommands: []*cli.Command{
		msigCreatePaymentConfirmationAuditCmd,
		msigCreateAuditCreatesCmd,
	},
}

var msigCreateAuditCreatesCmd = &cli.Command{
	Name:        "creates",
	Description: "produce an audit report of all created multisigs",
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		fmt.Printf("Hash,Address,ID,Balance,VestingAmount,VestingStart,VestingDuration,Signers\n")
		for _, job := range msd.Jobs {
			if job.ActorID == address.Undef {
				fmt.Printf("%s,,,,,,,\n", job.Params.Hash)
				continue
			}

			st, act, err := getMsigState(ctx, api, job.ActorID)
			if err != nil {
				return fmt.Errorf("failed to get state: %w", err)
			}

			actId, err := api.StateLookupID(ctx, job.ActorID, types.EmptyTSK)
			if err != nil {
				return fmt.Errorf("failed to lookup actor ID: %w", err)
			}

			fmt.Printf("%s,%s,%s,%s,%d,%d,%d,%s\n", job.Params.Hash, job.ActorID, actId, act.Balance, st.InitialBalance, st.StartEpoch, st.UnlockDuration, addrsToColonString(st.Signers))

		}
		return nil
	},
}

var msigCreatePaymentConfirmationAuditCmd = &cli.Command{
	Name:        "sends",
	Description: "output a csv of all the proposed sends for funding wallets",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "source",
			Usage: "source account to audit sends from",
		},
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		if cctx.String("source") == "" {
			return fmt.Errorf("must specify source multisig to audit sends from")
		}

		sourceAddr, err := address.NewFromString(cctx.String("source"))
		if err != nil {
			return fmt.Errorf("failed to parse 'source' address: %w", err)
		}

		act, err := api.StateGetActor(ctx, sourceAddr, types.EmptyTSK)
		if err != nil {
			return err
		}

		data, err := api.ChainReadObj(ctx, act.Head)
		if err != nil {
			return err
		}

		var msigst msig.State
		if err := msigst.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
			return err
		}

		ptxns, err := lcli.GetMultisigPending(ctx, api, msigst.PendingTxns)
		if err != nil {
			return err
		}

		type txnTracker struct {
			Txn *msig.Transaction
			ID  int64
		}

		bytarget := make(map[address.Address]txnTracker)
		for id, txn := range ptxns {
			bytarget[txn.To] = txnTracker{
				Txn: txn,
				ID:  id,
			}
		}

		fmt.Printf("WalletHash,WalletID,Signers,CurBalance,Proposer,TxnID,Value\n")
		for _, job := range msd.Jobs {
			tid := int64(-1)
			value := abi.NewTokenAmount(0)
			var proposer address.Address
			txn, ok := bytarget[job.ActorID]
			if ok {
				tid = txn.ID
				value = txn.Txn.Value
				proposer = txn.Txn.Approved[0]
			}

			act, err := api.StateGetActor(ctx, job.ActorID, types.EmptyTSK)
			if err != nil {
				return fmt.Errorf("failed to get actor %s: %w", job.ActorID, err)
			}

			fmt.Printf("%s,%s,%s,%s,%s,%d,%s\n", job.Params.Hash, job.ActorID, addrsToColonString(msigst.Signers), types.FIL(act.Balance), proposer, tid, types.FIL(value))
		}

		return nil
	},
}

func addrsToColonString(addrs []address.Address) string {
	var a []string
	for _, s := range addrs {
		a = append(a, s.String())
	}
	return strings.Join(a, ":")

}

func getMsigState(ctx context.Context, api api.FullNode, addr address.Address) (*msig.State, *types.Actor, error) {
	act, err := api.StateGetActor(ctx, addr, types.EmptyTSK)
	if err != nil {
		return nil, nil, err
	}

	data, err := api.ChainReadObj(ctx, act.Head)
	if err != nil {
		return nil, nil, err
	}

	var msigst msig.State
	if err := msigst.UnmarshalCBOR(bytes.NewReader(data)); err != nil {
		return nil, nil, err
	}

	return &msigst, act, nil
}

var msigCreateOutputCsvCmd = &cli.Command{
	Name:        "output-csv",
	Description: "generate output csv with created addresses and message ID",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		fmt.Println("Name,Entity,Hash,Amount,VestingMonths,MultisigM,MultisigN,Addresses,ActorID,MessageID")
		for _, job := range msd.Jobs {
			fmt.Printf("%s,%s,%s,%s,%d,%d,%d,%s,%s,%s\n", job.Params.Name, job.Params.Entity, job.Params.Hash, job.Params.Amount, job.Params.VestingMonths, job.Params.MultisigM, job.Params.MultisigN, addrsToColonString(job.Params.Addresses), job.ActorID, job.CreateCID)
		}
		return nil
	},
}

func loadMsd(fname string) (*MsigCreationData, error) {
	fi, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fi.Close()

	var msd MsigCreationData
	if err := json.NewDecoder(fi).Decode(&msd); err != nil {
		return nil, err
	}

	return &msd, nil
}

var msigCreateRemoveAdminsCmd = &cli.Command{
	Name: "remove-admins",
	Subcommands: []*cli.Command{
		msigCreateRemoveAdminsProposeCmd,
	},
}

var msigCreateRemoveAdminsProposeCmd = &cli.Command{
	Name:        "propose",
	Description: "proposes removal of admin addresses from wallets",
	Flags:       []cli.Flag{},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		api, closer, err := lcli.GetFullNodeAPI(cctx)
		if err != nil {
			return err
		}

		defer closer()
		ctx := lcli.ReqContext(cctx)

		msd, err := loadMsd(cctx.Args().First())
		if err != nil {
			return err
		}

		writeProgress := getProgressWriter(cctx.Args().First(), msd)

		// First, ensure the wallets have the other addresses set on them properly
		for _, job := range msd.Jobs {
			mstate, _, err := getMsigState(ctx, api, job.ActorID)
			if err != nil {
				return err
			}

			signers := make(map[address.Address]bool)
			for _, s := range mstate.Signers {
				signers[s] = true
			}

			for _, expSig := range job.Params.Addresses {
				idAddr, err := api.StateLookupID(ctx, expSig, types.EmptyTSK)
				if err != nil {
					return err
				}

				if !signers[idAddr] {
					return fmt.Errorf("wallet %s (%s) should have %s as a signer but does not", job.ActorID, jobStr(job), expSig)
				}
			}
		}

		for _, job := range msd.Jobs {
			if job.AdminRemovals == nil {
				job.AdminRemovals = make(map[string]cid.Cid)
			}

			for _, a := range msd.AdminAux {
				params := &msig.RemoveSignerParams{Signer: a}

				propCid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.RemoveSigner)
				if err != nil {
					return fmt.Errorf("failed to propose removal: %w", err)
				}

				job.AdminRemovals[a.String()] = propCid
				if err := writeProgress(); err != nil {
					return err
				}
			}

			params := &msig.RemoveSignerParams{Signer: msd.Creator}

			propCid, err := msigPropose(ctx, api, msd.Creator, job.ActorID, params, builtin.MethodsMultisig.RemoveSigner)
			if err != nil {
				return fmt.Errorf("failed to propose removal: %w", err)
			}

			job.AdminRemovals[msd.Creator.String()] = propCid
			if err := writeProgress(); err != nil {
				return err
			}
		}

		return nil
	},
}

func getProgressWriter(fname string, msd *MsigCreationData) func() error {
	return func() error {
		data, err := json.Marshal(msd)
		if err != nil {
			return fmt.Errorf("failed to marshal data: %w", err)
		}

		return ioutil.WriteFile(fname, data, 644)
	}
}
