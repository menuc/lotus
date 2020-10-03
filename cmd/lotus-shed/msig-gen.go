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
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/minio/blake2b-simd"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/filecoin-project/go-address"
	"github.com/filecoin-project/go-state-types/abi"
	"github.com/filecoin-project/lotus/api"
	"github.com/filecoin-project/lotus/api/apibstore"
	"github.com/filecoin-project/lotus/chain/types"
	lcli "github.com/filecoin-project/lotus/cli"

	"github.com/filecoin-project/go-state-types/big"
	"github.com/filecoin-project/lotus/chain/actors/adt"
	"github.com/filecoin-project/lotus/chain/actors/builtin/multisig"
	"github.com/filecoin-project/specs-actors/actors/builtin"
	iact "github.com/filecoin-project/specs-actors/actors/builtin/init"
	msig "github.com/filecoin-project/specs-actors/actors/builtin/multisig"
)

var custodianWhitelist = map[string]bool{
	"coinlist":       true,
	"coinbase":       true,
	"gemini":         true,
	"anchorage":      true,
	"self-glif":      true,
	"self-other":     true,
	"self-polychain": true,
}

const defaultProgressFileName = "msig-creation-progress.json"

const masterProgressFileName = "master-validation-progress.json"

const blocksInADay = (24 * 60 * 60) / 30
const blocksInAMonth = (blocksInADay * 365) / 12

type CreateParams struct {
	Name          string
	Entity        string
	Email         string
	Hash          string
	Amount        string
	VestingMonths int
	Custodian     string
	MultisigM     int
	MultisigN     int
	Addresses     []address.Address

	OutAddress          address.Address
	OutCreateMsg        cid.Cid
	ApprovalForTransfer bool
}

func jobStr(job *MsigCreationProgress) string {
	return fmt.Sprintf("%s %s %s", job.Params.Name, job.Params.Custodian, job.Params.Entity)
}

type MsigCreationProgress struct {
	Params    CreateParams
	CreateCID cid.Cid
	ActorID   address.Address

	AddAddrCids []cid.Cid

	SetThresholdCID cid.Cid

	AdminRemovals map[string]cid.Cid

	CreatorRemoveApprovals []cid.Cid
	//

	SetVestingCID       cid.Cid
	SetVestingApprovals []cid.Cid
	FundsLocked         bool

	ThresholdSet     bool
	RemoveControlCID cid.Cid
	ControlChanged   bool

	Complete bool

	SentFunds cid.Cid
}

type MsigCreationData struct {
	Jobs              []*MsigCreationProgress
	Creator           address.Address
	AdminAux          []address.Address
	SkipRemove        bool // TODO: deleteme
	VestingStartEpoch abi.ChainEpoch
}

func (msd *MsigCreationData) findJob(hash string) *MsigCreationProgress {
	for _, j := range msd.Jobs {
		if j.Params.Hash == hash {
			return j
		}
	}
	return nil
}

var createMsigsCmd = &cli.Command{
	Name: "create-msigs",
	Subcommands: []*cli.Command{
		msigCreateStartCmd,
		msigCreateCheckCreationCmd,
		msigCreateSetupCmd,
		msigCreateSetVestingCmd,
		msigCreateFillCmd,
		msigCreateAuditsCmd,
		msigCreateRemoveAdminsCmd,
		msigCreateOutputCsvCmd,
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
	},
	Action: func(cctx *cli.Context) error {
		if !cctx.Args().Present() {
			return fmt.Errorf("must pass input file")
		}

		if _, err := os.Stat(defaultProgressFileName); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("%q already exists, creation job already in progress?", defaultProgressFileName)
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

		inputCsv := cctx.Args().First()
		params, err := parseCreationCsv(inputCsv)
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
			createCid, err := api.MsigCreate(ctx, 1, []address.Address{createAddr}, 0, types.NewInt(0), createAddr, types.NewInt(0))
			if err != nil {
				return xerrors.Errorf("failed to create multisigs: %w", err)
			}

			cd.Jobs = append(cd.Jobs, &MsigCreationProgress{
				Params:    p,
				CreateCID: createCid,
			})
			fmt.Printf("created multisig for %s in %s\n", p.Hash, createCid)
		}

		fi, err := os.Create(defaultProgressFileName)
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

func parseCreationCsv(fname string) ([]CreateParams, error) {
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
		if len(r) < 13 {
			return nil, fmt.Errorf("records on row %d were invalid", i)
		}

		amt, err := types.ParseFIL(r[4])
		if err != nil {
			return nil, fmt.Errorf("failed to parse value field of row %d: %w", i, err)
		}

		vmonths, err := strconv.Atoi(r[6])
		if err != nil {
			return nil, fmt.Errorf("failed to parse vesting months field of row %d: %w", i, err)
		}

		msigM, err := strconv.Atoi(r[7])
		if err != nil {
			return nil, fmt.Errorf("failed to parse msigM field of row %d: %w", i, err)
		}

		msigN, err := strconv.Atoi(r[8])
		if err != nil {
			return nil, fmt.Errorf("failed to parse msigN field of row %d: %w", i, err)
		}

		addrDups := make(map[address.Address]bool)
		var addresses []address.Address
		for j, a := range strings.Split(r[9], ":") {
			addr, err := address.NewFromString(strings.TrimSpace(a))
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %d on row %d: %w", j, i, err)
			}
			if addrDups[addr] {
				return nil, fmt.Errorf("address %s in row %d is duplicated", addr, i)
			}
			addrDups[addr] = true
			addresses = append(addresses, addr)
		}
		if len(addresses) != msigN {
			return nil, fmt.Errorf("length of addresses set in row %d does not match multisig N field", i)
		}
		if msigM > len(addresses) {
			return nil, fmt.Errorf("row %d: M value greater than number of addresses", i)
		}

		var addr address.Address
		if r[10] != "" {
			ca, err := address.NewFromString(r[10])
			if err != nil {
				return nil, xerrors.Errorf("actor ID field invalid (row %d): %w", i, err)
			}
			addr = ca
		}

		var msgCid cid.Cid
		if r[11] != "" {
			mc, err := cid.Decode(r[11])
			if err != nil {
				return nil, xerrors.Errorf("failed to decode msg cid (row %d): %w", i, err)
			}

			msgCid = mc
		}

		var approval bool
		if r[12] != "" {
			low := strings.ToLower(r[12])
			if low == "true" {
				approval = true
			} else if low != "false" {
				return nil, fmt.Errorf("expected either 'true' or 'false' in ApprovalForTransfer in row %d", i)
			}
		}

		p := CreateParams{
			Name:                r[0],
			Entity:              r[1],
			Email:               r[2],
			Hash:                r[3],
			Amount:              strings.TrimSuffix(amt.String(), " FIL"),
			VestingMonths:       vmonths,
			Custodian:           r[5],
			MultisigM:           msigM,
			MultisigN:           msigN,
			Addresses:           addresses,
			OutAddress:          addr,
			OutCreateMsg:        msgCid,
			ApprovalForTransfer: approval,
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

var msigCreateSetupCmd = &cli.Command{
	Name:        "setup",
	Description: "setup wallets for a particular custodian after creation",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "specify the custodian to run wallet setup for",
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

		progressFname := cctx.Args().Get(0)
		inputCsv := cctx.Args().Get(1)

		masterCsv, err := parseCreationCsv(inputCsv)
		if err != nil {
			return err
		}

		msd, err := loadMsd(progressFname)
		if err != nil {
			return err
		}

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run wallet setup for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		writeProgress := getProgressWriter(progressFname, msd)

		// filter out just the rows we're going to work with
		var jobs []*MsigCreationProgress
		for _, inp := range masterCsv {
			if inp.Custodian != custodian {
				continue
			}

			// some sanity checking...
			job := msd.findJob(inp.Hash)
			if job == nil {
				return fmt.Errorf("account %s was not in the original master csv file", inp.Hash)
			}

			if inp.MultisigM > 1+len(msd.AdminAux) {
				return fmt.Errorf("not enough aux admin addresses for account %s (need %d total)", job.Params.Hash, inp.MultisigM)
			}

			if job.ActorID == address.Undef {
				return fmt.Errorf("actor creation for %s has not completed", job.Params.Hash)
			}

			if job.Params.MultisigM == 0 {
				return fmt.Errorf("account %s does not have M set", job.Params.Hash)
			}

			if job.ActorID != inp.OutAddress {
				return fmt.Errorf("master csv Actor address did not match creation progress data for %s", job.Params.Hash)
			}

			job.Params = inp
			jobs = append(jobs, job)
		}

		fmt.Printf("Found %d accounts for custodian %q\n", len(jobs), custodian)

		for _, j := range jobs {
			st, _, err := getMsigState(ctx, api, j.ActorID)
			if err != nil {
				return err
			}

			if st.NumApprovalsThreshold != 1 {
				fmt.Printf("actor %s for account %s already has threshold of %d, refusing to change address set (already in progress?)\n", j.ActorID, j.Params.Hash, st.NumApprovalsThreshold)
				continue
			}

			if len(j.AddAddrCids) > 0 {
				fmt.Printf("account %s already has 'AddAddrs' proposed\n", j.Params.Hash)

				if len(j.AddAddrCids)+1 != j.Params.MultisigM+j.Params.MultisigN {
					// if less than the required amount, we could potentially continue here...
					return fmt.Errorf("account %s has incorrect number of add address proposals: expected %d, have %d", j.Params.Hash, j.Params.MultisigN+j.Params.MultisigM-1, len(j.AddAddrCids))
				}

				// already proposed addAddrs, i guess we can continue
				continue
			}

			nControlAdd := j.Params.MultisigM - 1
			toAdd := make([]address.Address, j.Params.MultisigN+nControlAdd)
			copy(toAdd, msd.AdminAux[:nControlAdd])
			copy(toAdd[nControlAdd:], j.Params.Addresses)

			fmt.Printf("adding %d keys for account %s\n", len(toAdd), j.Params.Hash)
			for i, a := range toAdd {
				addSigner := &msig.AddSignerParams{
					Signer: a,
				}

				mcid, err := msigPropose(ctx, api, msd.Creator, j.ActorID, addSigner, builtin.MethodsMultisig.AddSigner)
				if err != nil {
					return fmt.Errorf("failed to propose add signer: %w", err)
				}

				fmt.Printf("\t%d / %d - adding %s in %s\n", i+1, len(toAdd), a, mcid)
				j.AddAddrCids = append(j.AddAddrCids, mcid)
				if err := writeProgress(); err != nil {
					return fmt.Errorf("failed to write progress: %w", err)
				}
			}
		}

		// Now wait for all the adds to land
		for i, j := range jobs {
			fmt.Printf("%d / %d - Waiting for add signer for %s\n", i+1, len(jobs), j.Params.Hash)
			for _, c := range j.AddAddrCids {
				lookup, err := api.StateWaitMsg(ctx, c, 4)
				if err != nil {
					return fmt.Errorf("waiting for %s of account %s failed: %w", c, j.Params.Hash, err)
				}

				if lookup.Receipt.ExitCode != 0 {
					return fmt.Errorf("add signer msg %s of account %s failed: exit code %d", c, j.Params.Hash, lookup.Receipt.ExitCode)
				}
			}
		}

		// Verify all addresses were correctly added
		for i, j := range jobs {
			fmt.Printf("%d / %d - Checking account state for %s\n", i, len(jobs), j.Params.Hash)

			msigst, _, err := getMsigState(ctx, api, j.ActorID)
			if err != nil {
				return err
			}

			expAddrs := []address.Address{msd.Creator}
			expAddrs = append(expAddrs, msd.AdminAux[:j.Params.MultisigM-1]...)
			expAddrs = append(expAddrs, j.Params.Addresses...)

			pubSigs, err := toPublicKeys(ctx, api, msigst.Signers)
			if err != nil {
				return err
			}
			if !addressSetsMatch(pubSigs, expAddrs) {
				return fmt.Errorf("addresses in state did not match for account %s (%s): expected %v, got %v", j.Params.Hash, j.ActorID, expAddrs, pubSigs)
			}
		}

		// Set the multisig threshold
		for i, j := range jobs {
			if j.Params.MultisigM == 1 {
				fmt.Printf("%d / %d - setting approval threshold for %s, M=1, no action necessary\n", i, len(jobs), j.Params.Hash)
				continue
			}

			if j.SetThresholdCID != cid.Undef {
				fmt.Printf("set approval threshold proposal already sent for %s in %s\n", j.Params.Hash, j.SetThresholdCID)
				continue
			}

			changeThresh := &msig.ChangeNumApprovalsThresholdParams{
				NewThreshold: uint64(j.Params.MultisigM),
			}

			mcid, err := msigPropose(ctx, api, msd.Creator, j.ActorID, changeThresh, builtin.MethodsMultisig.ChangeNumApprovalsThreshold)
			if err != nil {
				return fmt.Errorf("failed to propose set threshold for %s: %w", j.Params.Hash, err)
			}
			fmt.Printf("%d / %d - setting approval threshold for %s to %d in %s\n", i, len(jobs), j.Params.Hash, changeThresh.NewThreshold, mcid)

			j.SetThresholdCID = mcid
			if err := writeProgress(); err != nil {
				return fmt.Errorf("failed to write progress: %w", err)
			}
		}

		// now wait for all the threshold sets to land on chain
		for i, j := range jobs {
			if j.Params.MultisigM == 1 {
				fmt.Printf("%d / %d - Desired M is already 1, no action necessary for %s\n", i, len(jobs), j.Params.Hash)
				continue
			}

			if j.SetThresholdCID == cid.Undef {
				return fmt.Errorf("no set threshold cid found for %s", j.Params.Hash)
			}
			fmt.Printf("%d / %d - Waiting for set threshold for %s\n", i, len(jobs), j.Params.Hash)
			lookup, err := api.StateWaitMsg(ctx, j.SetThresholdCID, 4)
			if err != nil {
				return fmt.Errorf("waiting for set threshold (%s) of account %s failed: %w", j.SetThresholdCID, j.Params.Hash, err)
			}

			if lookup.Receipt.ExitCode != 0 {
				return fmt.Errorf("set threshold msg %s of account %s failed: exit code %d", j.SetThresholdCID, j.Params.Hash, lookup.Receipt.ExitCode)
			}
		}

		// Verify threshold has been correctly changed
		for _, j := range jobs {
			msigst, _, err := getMsigState(ctx, api, j.ActorID)
			if err != nil {
				return err
			}
			if msigst.NumApprovalsThreshold != uint64(j.Params.MultisigM) {
				return fmt.Errorf("failed to properly set multisig threshold for %s", j.Params.Hash)
			}
		}

		return nil
	},
}

func addressSetsMatch(a, b []address.Address) bool {
	if len(a) != len(b) {
		return false
	}

	setA := make(map[address.Address]bool)
	for _, addr := range a {
		setA[addr] = true
	}

	setB := make(map[address.Address]bool) // guard against duplicates causing a subset to validate as the same [a, b ,c] != [a, a, c]
	for _, addr := range b {
		setB[addr] = true
		if !setA[addr] {
			return false
		}
	}
	if len(setA) != len(setB) {
		return false
	}
	return true
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
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "specify the custodian to run wallet setup for",
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

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run set-vesting for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		var jobs []*MsigCreationProgress
		for _, job := range msd.Jobs {
			if job.ActorID == address.Undef {
				fmt.Printf("actor creation not yet complete for %s. Please run 'check-creation'\n", jobStr(job))
				return nil
			}

			if job.Params.Custodian == custodian {
				jobs = append(jobs, job)
			}
		}

		fmt.Printf("Running vesting configuration for %d wallets from %s\n", len(jobs), custodian)

		for _, job := range jobs {
			if job.SetVestingCID != cid.Undef {
				fmt.Printf("vesting proposal already sent for %s, skipping...\n", job.Params.Hash)
				continue
			}
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
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "specify the custodian to run wallet setup for",
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

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run set-vesting for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		var jobs []*MsigCreationProgress
		for _, job := range msd.Jobs {
			if job.Params.Custodian != custodian {
				continue
			}

			if job.SetVestingCID == cid.Undef {
				fmt.Printf("set vesting operation not yet proposed for %s. Please run 'set-vesting propose'", jobStr(job))
				return nil
			}

			jobs = append(jobs, job)
		}

		fmt.Printf("Hash,SetVestingCID,Applied,ActorID,TxnID,Error\n")
		for _, job := range jobs {
			pr, err := checkProposeReceipt(ctx, api, job.SetVestingCID)
			if err != nil {
				errstr := fmt.Sprintf("set vesting not complete: %s", err)
				fmt.Printf("%s,%s,false,%s,-1,%s\n", job.Params.Hash, job.SetVestingCID, job.ActorID, errstr)
				continue
			}

			if pr.Applied {
				fmt.Printf("%s,%s,true,%s,%d,\n", job.Params.Hash, job.SetVestingCID, job.ActorID, -1)
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
		&cli.BoolFlag{
			Name: "force",
		},
	},
	Action: func(cctx *cli.Context) error {
		if cctx.Args().Len() != 2 {
			return fmt.Errorf("must pass progress file and set-vesting check file")
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

		fi, err := os.Open(cctx.Args().Get(1))
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
				return fmt.Errorf("decoding cid %s: %w", r[1], err)
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

		var complete int
		for _, svr := range svrows {
			j := msd.findJob(svr.Hash)
			if !cctx.Bool("force") && j.Params.MultisigM <= 1+len(j.SetVestingApprovals) {
				fmt.Printf("Job %s has sufficient approvals already\n", svr.Hash)
				complete++
				continue
			}
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
				fmt.Printf("mpool push message failed: %s", err)
				continue
			}

			j.SetVestingApprovals = append(j.SetVestingApprovals, sm.Cid())
			if err := writeProgress(); err != nil {
				return fmt.Errorf("failed to save approval cid: %w", err)
			}

			fmt.Printf("approved txn %d on %s in msg %s\n", svr.TxnID, svr.ActorID, sm.Cid())
		}

		for _, svr := range svrows {
			j := msd.findJob(svr.Hash)

			for i, appcid := range j.SetVestingApprovals {
				fmt.Printf("waiting for approval %d / %d for account %s to land on chain (msdcid: %s)\n", i, len(j.SetVestingApprovals), j.Params.Hash, appcid)
				lookup, err := api.StateWaitMsg(ctx, appcid, 4)
				if err != nil {
					return fmt.Errorf("failed to wait for msg on chain: %w", err)
				}

				if lookup.Receipt.ExitCode != 0 {
					return fmt.Errorf("set-vesting approval (%s) for account %s failed with exit code %d", appcid, j.Params.Hash, lookup.Receipt.ExitCode)
				}
			}
		}

		fmt.Printf("%d / %d jobs complete\n", complete, len(svrows))

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
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "specify the custodian to run wallet setup for",
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

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run set-vesting for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		var jobs []*MsigCreationProgress
		for _, job := range msd.Jobs {
			if job.Params.Custodian != custodian {
				continue
			}

			if !job.FundsLocked {
				return fmt.Errorf("vesting schedule not set for all wallets yet, please set vesting before sending funds")
			}
			jobs = append(jobs, job)
		}

		fmt.Printf("sending funding proposals for %d accounts from %s\n", len(jobs), custodian)

		for _, job := range jobs {
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
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "optionally filter by a particular custodian",
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

		custodian := cctx.String("custodian")
		fmt.Printf("Hash,Address,ID,Balance,VestingAmount,VestingStart,VestingDuration,MultisigM,Signers\n")
		for _, job := range msd.Jobs {
			if custodian != "" && job.Params.Custodian != custodian {
				continue
			}

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

			kaddrs, err := toPublicKeys(ctx, api, st.Signers)
			if err != nil {
				return fmt.Errorf("failed to lookup public keys for signers: %w", err)
			}

			fmt.Printf("%s,%s,%s,%s,%d,%d,%d,%d,%s\n", job.Params.Hash, job.ActorID, actId, act.Balance, st.InitialBalance, st.StartEpoch, st.UnlockDuration, st.NumApprovalsThreshold, addrsToColonString(kaddrs))

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
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "custodian to audit sends for",
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

		store := adt.WrapStore(ctx, cbor.NewCborStore(apibstore.NewAPIBlockstore(api)))
		act, err := api.StateGetActor(ctx, sourceAddr, types.EmptyTSK)
		if err != nil {
			return err
		}

		msigst, err := multisig.Load(store, act)
		if err != nil {
			return err
		}

		type txnTracker struct {
			Txn multisig.Transaction
			ID  int64
		}

		bytarget := make(map[address.Address]txnTracker)
		if err := msigst.ForEachPendingTxn(func(id int64, txn multisig.Transaction) error {
			bytarget[txn.To] = txnTracker{
				Txn: txn,
				ID:  id,
			}
			return nil
		}); err != nil {
			return err
		}

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run funding audit for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		var jobs []*MsigCreationProgress
		for _, job := range msd.Jobs {
			if job.Params.Custodian == custodian {
				jobs = append(jobs, job)
			}
		}

		fmt.Printf("Hash,WalletID,Signers,CurBalance,Proposer,TxnID,Value,LockedAmount\n")
		for _, job := range jobs {
			tid := int64(-1)
			value := abi.NewTokenAmount(0)
			var proposer address.Address
			txn, ok := bytarget[job.ActorID]
			if ok {
				tid = txn.ID
				value = txn.Txn.Value
				proposer = txn.Txn.Approved[0]
			}

			st, act, err := getMsigState(ctx, api, job.ActorID)
			if err != nil {
				return fmt.Errorf("failed to look up multisig state: %w", err)
			}

			signers, err := msigst.Signers()
			if err != nil {
				return err
			}

			fmt.Printf("%s,%s,%s,%s,%s,%d,%s,%s\n", job.Params.Hash, job.ActorID, addrsToColonString(signers), types.FIL(act.Balance), proposer, tid, types.FIL(value), types.FIL(st.InitialBalance))
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

		fmt.Println("Name,Entity,Email,Hash,Amount,Custodian,VestingMonths,MultisigM,MultisigN,Addresses,ActorID,MessageID")
		for _, job := range msd.Jobs {
			fmt.Printf("%s,%q,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s\n", job.Params.Name, job.Params.Entity, job.Params.Email, job.Params.Hash, job.Params.Amount, job.Params.Custodian, job.Params.VestingMonths, job.Params.MultisigM, job.Params.MultisigN, addrsToColonString(job.Params.Addresses), job.ActorID, job.CreateCID)
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
	Name:        "remove-admins",
	Description: "proposes removal of admin addresses from wallets",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "custodian",
			Usage: "custodian to audit sends for",
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

		custodian := cctx.String("custodian")
		if custodian == "" {
			return fmt.Errorf("must specify custodian to run set-vesting for")
		}
		if !custodianWhitelist[custodian] {
			return fmt.Errorf("%q is not a whitelisted custodian", custodian)
		}

		var jobs []*MsigCreationProgress
		for _, job := range msd.Jobs {
			if job.Params.Custodian == custodian {
				jobs = append(jobs, job)
			}
		}

		// First, ensure the wallets have the other addresses set on them properly
		for _, job := range jobs {
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

		for _, job := range jobs {
			if job.AdminRemovals == nil {
				job.AdminRemovals = make(map[string]cid.Cid)
			}

			numAux := job.Params.MultisigM - 1
			for _, a := range append([]address.Address{msd.Creator}, msd.AdminAux[:numAux]...) {
				if _, ok := job.AdminRemovals[a.String()]; ok {
					fmt.Printf("Account %s already proposed removal of admin key %s\n", job.Params.Hash, a)
					continue
				}
				params := &msig.RemoveSignerParams{Signer: a}

				propCid, err := msigPropose(ctx, api, a, job.ActorID, params, builtin.MethodsMultisig.RemoveSigner)
				if err != nil {
					return fmt.Errorf("failed to propose removal: %w", err)
				}

				job.AdminRemovals[a.String()] = propCid
				if err := writeProgress(); err != nil {
					return err
				}
				fmt.Printf("Account %s (addr %s) proposed removal of %s in %s\n", job.Params.Hash, job.ActorID, a, propCid)
			}
		}

		for _, job := range jobs {
			// Now wait for all those to complete...
			for addr, c := range job.AdminRemovals {
				fmt.Printf("wait for removal proposal of %s on account %s (%s)\n", addr, job.Params.Hash, c)
				lookup, err := api.StateWaitMsg(ctx, c, 4)
				if err != nil {
					return err
				}

				if lookup.Receipt.ExitCode != 0 {
					return fmt.Errorf("remove proposal %s failed: exitcode %d", c, lookup.Receipt.ExitCode)
				}
			}
		}

		// For accounts with M > 1, approve the removal of our first key

		complete := 0
		for loop := 0; complete < len(jobs); loop++ {
			for _, job := range jobs {
				if job.Params.MultisigM == 1 {
					complete++
					continue
				}

				propCid := job.AdminRemovals[msd.Creator.String()]
				propRet, err := checkProposeReceipt(ctx, api, propCid)
				if err != nil {
					return err
				}

				_, act, err := getMsigState(ctx, api, job.ActorID)
				if err != nil {
					return err
				}

				store := adt.WrapStore(ctx, cbor.NewCborStore(apibstore.NewAPIBlockstore(api)))
				msigst, err := multisig.Load(store, act)
				if err != nil {
					return err
				}

				var found bool
				if err := msigst.ForEachPendingTxn(func(id int64, txn multisig.Transaction) error {
					if id == int64(propRet.TxnID) {
						found = true
					}
					return nil
				}); err != nil {
					return err
				}

				if !found {
					fmt.Printf("proposal to remove address (%s) no longer found on chain...\n", propCid)
					continue
				}

				numAux := job.Params.MultisigM - 1

				if len(job.CreatorRemoveApprovals) >= numAux {
					fmt.Printf("Already have enough approvals for %s (%s)\n", job.Params.Hash, job.ActorID)
					complete++
					continue
				}

				next := msd.AdminAux[len(job.CreatorRemoveApprovals)]
				fmt.Printf("Approving txn %d for account %s (%s) with key %s\n", propRet.TxnID, job.Params.Hash, job.ActorID, next)
				params := &msig.TxnIDParams{
					ID: propRet.TxnID,
				}

				buf := new(bytes.Buffer)
				if err := params.MarshalCBOR(buf); err != nil {
					return err
				}

				msg := &types.Message{
					To:     job.ActorID,
					From:   next,
					Method: builtin.MethodsMultisig.Approve,
					Params: buf.Bytes(),
				}

				smsg, err := api.MpoolPushMessage(ctx, msg, nil)
				if err != nil {
					return err
				}

				fmt.Printf("approved removal of %s in %s\n", msd.Creator, smsg.Cid())
				job.CreatorRemoveApprovals = append(job.CreatorRemoveApprovals, smsg.Cid())
				if err := writeProgress(); err != nil {
					return fmt.Errorf("failed to write progress: %w", err)
				}
			}

			for _, job := range jobs {
				for _, apc := range job.CreatorRemoveApprovals {
					fmt.Printf("waiting for confirmation on creator removal: %s\n", apc)
					lookup, err := api.StateWaitMsg(ctx, apc, 4)
					if err != nil {
						return fmt.Errorf("failed to wait for msg: %w", err)
					}

					if lookup.Receipt.ExitCode != 0 {
						return fmt.Errorf("approval failed: exitcode %d", lookup.Receipt.ExitCode)
					}
				}
			}

		}

		return nil
	},
}

func toPublicKeys(ctx context.Context, api api.FullNode, addrs []address.Address) ([]address.Address, error) {
	var out []address.Address
	for _, a := range addrs {
		k, err := api.StateAccountKey(ctx, a, types.EmptyTSK)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
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
