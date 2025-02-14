package keeper

import (
	"context"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/pkg/errors"
	"github.com/smartcontractkit/chainlink/core/logger"
	"github.com/smartcontractkit/chainlink/core/services/eth"
	"github.com/smartcontractkit/chainlink/core/services/gas"
	httypes "github.com/smartcontractkit/chainlink/core/services/headtracker/types"
	"github.com/smartcontractkit/chainlink/core/services/job"
	"github.com/smartcontractkit/chainlink/core/services/pipeline"
	"github.com/smartcontractkit/chainlink/core/services/postgres"
	"github.com/smartcontractkit/chainlink/core/utils"
	bigmath "github.com/smartcontractkit/chainlink/core/utils/big_math"
)

const (
	executionQueueSize = 10
)

// UpkeepExecuter fulfills Service and HeadTrackable interfaces
var (
	_ job.Service           = (*UpkeepExecuter)(nil)
	_ httypes.HeadTrackable = (*UpkeepExecuter)(nil)
)

// UpkeepExecuter implements the logic to communicate with KeeperRegistry
type UpkeepExecuter struct {
	chStop          chan struct{}
	ethClient       eth.Client
	config          Config
	executionQueue  chan struct{}
	headBroadcaster httypes.HeadBroadcasterRegistry
	gasEstimator    gas.Estimator
	job             job.Job
	mailbox         *utils.Mailbox
	orm             ORM
	pr              pipeline.Runner
	logger          logger.Logger
	wgDone          sync.WaitGroup
	utils.StartStopOnce
}

// NewUpkeepExecuter is the constructor of UpkeepExecuter
func NewUpkeepExecuter(
	job job.Job,
	orm ORM,
	pr pipeline.Runner,
	ethClient eth.Client,
	headBroadcaster httypes.HeadBroadcaster,
	gasEstimator gas.Estimator,
	logger logger.Logger,
	config Config,
) *UpkeepExecuter {
	return &UpkeepExecuter{
		chStop:          make(chan struct{}),
		ethClient:       ethClient,
		executionQueue:  make(chan struct{}, executionQueueSize),
		headBroadcaster: headBroadcaster,
		gasEstimator:    gasEstimator,
		job:             job,
		mailbox:         utils.NewMailbox(1),
		config:          config,
		orm:             orm,
		pr:              pr,
		logger:          logger,
	}
}

// Start starts the upkeep executer logic
func (ex *UpkeepExecuter) Start() error {
	return ex.StartOnce("UpkeepExecuter", func() error {
		ex.wgDone.Add(2)
		go ex.run()
		latestHead, unsubscribeHeads := ex.headBroadcaster.Subscribe(ex)
		if latestHead != nil {
			ex.mailbox.Deliver(*latestHead)
		}
		go func() {
			defer unsubscribeHeads()
			defer ex.wgDone.Done()
			<-ex.chStop
		}()
		return nil
	})
}

// Close stops and closes upkeep executer
func (ex *UpkeepExecuter) Close() error {
	return ex.StopOnce("UpkeepExecuter", func() error {
		close(ex.chStop)
		ex.wgDone.Wait()
		return nil
	})
}

// OnNewLongestChain handles the given head of a new longest chain
func (ex *UpkeepExecuter) OnNewLongestChain(_ context.Context, head eth.Head) {
	ex.mailbox.Deliver(head)
}

func (ex *UpkeepExecuter) run() {
	defer ex.wgDone.Done()
	for {
		select {
		case <-ex.chStop:
			return
		case <-ex.mailbox.Notify():
			ex.processActiveUpkeeps()
		}
	}
}

func (ex *UpkeepExecuter) processActiveUpkeeps() {
	// Keepers could miss their turn in the turn taking algo if they are too overloaded
	// with work because processActiveUpkeeps() blocks
	item, exists := ex.mailbox.Retrieve()
	if !exists {
		ex.logger.Info("no head to retrieve. It might have been skipped")
		return
	}

	head, ok := item.(eth.Head)
	if !ok {
		ex.logger.Errorf("expected `eth.Head`, got %T", head)
		return
	}

	ex.logger.Debugw("checking active upkeeps", "blockheight", head.Number)

	ctx, cancel := postgres.DefaultQueryCtx()
	defer cancel()

	activeUpkeeps, err := ex.orm.EligibleUpkeepsForRegistry(
		ctx,
		ex.job.KeeperSpec.ContractAddress,
		head.Number,
		ex.config.KeeperMaximumGracePeriod(),
	)
	if err != nil {
		ex.logger.With("error", err).Error("unable to load active registrations")
		return
	}

	wg := sync.WaitGroup{}
	wg.Add(len(activeUpkeeps))
	done := func() {
		<-ex.executionQueue
		wg.Done()
	}
	for _, reg := range activeUpkeeps {
		ex.executionQueue <- struct{}{}
		go ex.execute(reg, head.Number, done)
	}

	wg.Wait()
}

// execute triggers the pipeline run
func (ex *UpkeepExecuter) execute(upkeep UpkeepRegistration, headNumber int64, done func()) {
	defer done()

	svcLogger := ex.logger.With("blockNum", headNumber, "upkeepID", upkeep.UpkeepID)
	svcLogger.Debug("checking upkeep")

	ctxService, cancel := utils.ContextFromChanWithDeadline(ex.chStop, time.Minute)
	defer cancel()

	gasPrice, err := ex.estimateGasPrice(upkeep)
	if err != nil {
		svcLogger.Error(errors.Wrap(err, "estimating gas price"))
		return
	}

	vars := pipeline.NewVarsFrom(map[string]interface{}{
		"jobSpec": map[string]interface{}{
			"jobID":                 ex.job.ID,
			"fromAddress":           upkeep.Registry.FromAddress.String(),
			"contractAddress":       upkeep.Registry.ContractAddress.String(),
			"upkeepID":              upkeep.UpkeepID,
			"performUpkeepGasLimit": upkeep.ExecuteGas + ex.orm.config.KeeperRegistryPerformGasOverhead(),
			"checkUpkeepGasLimit": ex.config.KeeperRegistryCheckGasOverhead() + uint64(upkeep.Registry.CheckGas) +
				ex.config.KeeperRegistryPerformGasOverhead() + upkeep.ExecuteGas,
			"gasPrice": gasPrice,
		},
	})

	run := pipeline.NewRun(*ex.job.PipelineSpec, vars)
	if _, err := ex.pr.Run(ctxService, &run, ex.logger, true, nil); err != nil {
		ex.logger.With("error", err).Errorw("failed executing run")
		return
	}

	// Only after task runs where a tx was broadcast
	if run.State == pipeline.RunStatusCompleted {
		err := ex.orm.SetLastRunHeightForUpkeepOnJob(ctxService, ex.job.ID, upkeep.UpkeepID, headNumber)
		if err != nil {
			ex.logger.With("error", err).Errorw("failed to set last run height for upkeep")
		}
	}
}

func (ex *UpkeepExecuter) estimateGasPrice(upkeep UpkeepRegistration) (*big.Int, error) {
	performTxData, err := RegistryABI.Pack(
		"performUpkeep",
		big.NewInt(upkeep.UpkeepID),
		common.Hex2Bytes("1234"), // placeholder
	)
	if err != nil {
		return nil, errors.Wrap(err, "unable to construct performUpkeep data")
	}
	gasPrice, _, err := ex.gasEstimator.EstimateGas(performTxData, upkeep.ExecuteGas)
	if err != nil {
		return nil, errors.Wrap(err, "unable to estimate gas")
	}
	// add GasPriceBuffer to gasPrice
	gasPrice = bigmath.Div(
		bigmath.Mul(gasPrice, 100+ex.config.KeeperGasPriceBufferPercent()),
		100,
	)
	return gasPrice, nil
}
