package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
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

type MsigCreationProgress struct {
	Params        CreateParams
	CreateCID     cid.Cid
	SetVestingCID cid.Cid
	ActorID       address.Address
	Complete      bool
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

		for _, job := range msd.Jobs {
			if job.ActorID == address.Undef {
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

				msg := &types.Message{
					From:   msd.Creator,
					To:     job.ActorID,
					Method: builtin.MethodsMultisig.LockBalance,
					Params: buf.Bytes(),
				}

				sm, err := api.MpoolPushMessage(ctx, msg, nil)
				if err != nil {
					return err
				}

				job.SetVestingCID = sm.Cid()
				if err := writeProgress(); err != nil {
					return err
				}
			}
		}

		return nil
	},
}
