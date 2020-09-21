package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/ipfs/go-cid"
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
}

type MsigCreationData struct {
	Jobs    []*MsigCreationProgress
	Creator address.Address
}

var createMsigsCmd = &cli.Command{
	Name: "create-msigs",
	Subcommands: []*cli.Command{
		msigCreateStartCmd,
		msigCreationStatusCmd,
		msigCreateNextCmd,
	},
}

var msigCreationStatusCmd = &cli.Command{
	Name:        "status",
	Description: "check status of multisig creation batch job",
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

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}

		var msd MsigCreationData
		if err := json.NewDecoder(fi).Decode(&msd); err != nil {
			return err
		}

		for _, job := range msd.Jobs {
			if job.CreateCID != cid.Undef {
				r, err := api.StateGetReceipt(ctx, job.CreateCID, types.EmptyTSK)
				if err != nil {
					return fmt.Errorf("failed to get receipt: %w", err)
				} else {
					if r == nil {
						fmt.Printf("no receipt found yet for %s\n", job.CreateCID)
					} else {
						if r.ExitCode != 0 {
							fmt.Printf("creation job failed for %s %s %s: %d\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, r.ExitCode)
						} else {
							var er iact.ExecReturn
							if err := er.UnmarshalCBOR(bytes.NewReader(r.Return)); err != nil {
								return xerrors.Errorf("return value of create message failed to parse: %w", err)
							}

							fmt.Printf("actor create successful: %s %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity, er.RobustAddress)
						}
					}
				}
			}
		}

		return nil
	},
}

var msigCreateStartCmd = &cli.Command{
	Name:        "start",
	Description: "start of multisig accounts creation, parses initial csv input and sends creation messages for each, recording the message cid in the output file",
	Flags: []cli.Flag{
		&cli.Uint64Flag{
			Name: "vesting-start",
		},
		&cli.StringFlag{
			Name:  "creator",
			Usage: "address to use as the creator and controller for the entire setup process",
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

		params, err := parseCreateParams(cctx.Args().First())
		if err != nil {
			return err
		}

		cd := &MsigCreationData{
			Creator: createAddr,
		}

		for _, p := range params {
			createCid, err := api.MsigCreate(ctx, 1, append(p.Addresses, createAddr), 0, types.NewInt(0), createAddr, types.NewInt(0))
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

var msigCreateNextCmd = &cli.Command{
	Name:        "next",
	Description: "perform next required processing for multisig creation",
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

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}

		var msd MsigCreationData
		if err := json.NewDecoder(fi).Decode(&msd); err != nil {
			return err
		}

		fi.Close()

		writeProgress := func() error {
			nfi, err := os.Create(cctx.Args().First())
			if err != nil {
				return fmt.Errorf("failed to open file: %w", err)
			}
			defer nfi.Close()

			if err := json.NewEncoder(nfi).Encode(&msd); err != nil {
				return fmt.Errorf("failed to write progress out to a file: %w", err)
			}

			return nil
		}

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
				const blocksInADay = (24 * 60 * 60) / 30
				const blocksInAMonth = (blocksInADay * 365) / 12
				params := msig.LockBalanceParams{
					StartEpoch:     0,
					UnlockDuration: abi.ChainEpoch(blocksInAMonth * job.Params.VestingMonths),
					Amount:         big.Int(famt),
				}

				buf := new(bytes.Buffer)
				if err := params.MarshalCBOR(buf); err != nil {
					return err
				}

				addr, err := api.StateLookupID(ctx, job.ActorID, types.EmptyTSK)
				if err != nil {
					fmt.Printf("failed to look up actor ID for %s (%s): %s", job.ActorID, job.Params.Name, err)
					continue
				}

				prop := msig.ProposeParams{
					To:     addr,
					Value:  abi.NewTokenAmount(0),
					Method: builtin.MethodsMultisig.LockBalance,
					Params: buf.Bytes(),
				}

				buf2 := new(bytes.Buffer)
				if err := prop.MarshalCBOR(buf2); err != nil {
					return err
				}

				msg := &types.Message{
					From:   msd.Creator,
					To:     addr,
					Method: builtin.MethodsMultisig.Propose,
					Params: buf2.Bytes(),
				}

				sm, err := api.MpoolPushMessage(ctx, msg, nil)
				if err != nil {
					return err
				}

				job.SetVestingCID = sm.Cid()
				if err := writeProgress(); err != nil {
					return err
				}
				fmt.Printf("proposed funds locking for %s in %s\n", job.Params.Name, sm.Cid())
			}

			if job.SetVestingCID.Defined() && !job.FundsLocked {
				fmt.Println("finding funds locking receipt for ", job.Params.Name)
				if err := checkProposeReceipt(ctx, api, job.SetVestingCID); err != nil {
					fmt.Printf("set vesting (%s %s %s) not complete: %s", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
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
				if err := checkProposeReceipt(ctx, api, job.SetThresholdCID); err != nil {
					fmt.Printf("set threshold (%s %s %s) not complete: %s", job.Params.Name, job.Params.Custodian, job.Params.Entity, err)
					continue
				}

				fmt.Printf("set threshold successful: %s %s %s\n", job.Params.Name, job.Params.Custodian, job.Params.Entity)
				job.ThresholdSet = true
				if err := writeProgress(); err != nil {
					return err
				}
			}
		}

		return nil
	},
}

func checkProposeReceipt(ctx context.Context, api api.FullNode, c cid.Cid) error {
	r, err := api.StateGetReceipt(ctx, c, types.EmptyTSK)
	if err != nil {
		return fmt.Errorf("finding receipt failed: %w", err)
	}

	if r == nil {
		return fmt.Errorf("message hasnt made it into the chain yet")
	}

	if r.ExitCode != 0 {
		return fmt.Errorf("propose receipt had nonzero exitcode: %d", r.ExitCode)
	}

	var pr msig.ProposeReturn
	if err := pr.UnmarshalCBOR(bytes.NewReader(r.Return)); err != nil {
		return xerrors.Errorf("return value of %s failed to parse: %w", c, err)
	}

	if pr.Code != 0 {
		return fmt.Errorf("multisig operation failed: %d", pr.Code)
	}

	if !pr.Applied {
		return fmt.Errorf("operation not applied")
	}

	return nil
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
		Method: builtin.MethodsMultisig.LockBalance,
		Params: buf.Bytes(),
	}

	buf2 := new(bytes.Buffer)
	if err := prop.MarshalCBOR(buf2); err != nil {
		return cid.Undef, err
	}

	msg := &types.Message{
		From:   sender,
		To:     addr,
		Method: method,
		Params: buf2.Bytes(),
	}

	sm, err := api.MpoolPushMessage(ctx, msg, nil)
	if err != nil {
		return cid.Undef, err
	}

	return sm.Cid(), nil

}

var msigCreationVerifyCmd = &cli.Command{
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

		fi, err := os.Open(cctx.Args().First())
		if err != nil {
			return err
		}

		var msd MsigCreationData
		if err := json.NewDecoder(fi).Decode(&msd); err != nil {
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

				fmt.Printf("\tID: %s", addr)

				fmt.Printf("\tBalance: %s\n", act.Balance)
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
				pf := color.Red
				if addrsCorrect {
					pf = color.Green
				}
				pf("\t%s\n", msigst.Signers)

			}
		}

		return nil
	},
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
