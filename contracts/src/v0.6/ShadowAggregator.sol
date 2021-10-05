// SPDX-License-Identifier: MIT
pragma solidity 0.6.6;

import "./Median.sol";
import "./Owned.sol";
import "./interfaces/AggregatorV3Interface.sol";
import "./vendor/SafeMathChainlink.sol";

/**
 * @title The Prepaid Aggregator contract
 * @notice Handles aggregating data pushed in from off-chain. Oracles' submissions are gathered in
 * rounds, with each round aggregating the submissions for each oracle into a
 * single answer. The latest aggregated answer is exposed as well as historical
 * answers and their updated at timestamp.
 */
contract ShadowAggregator is AggregatorV3Interface, Owned {
  using SafeMathChainlink for uint256;

  enum Role{Unset, Transmitter, Signer}

  struct Round {
    int256 answer;
    uint256 startedAt;
    uint256 updatedAt;
    uint80 answeredInRound;
  }

  struct Oracle {
    uint16 index;
    Role role;
  }

  AggregatorV3Interface public aggregator;

  uint8 private dcls;
  string private desc;

  uint256 constant private MAX_ORACLE_COUNT = 25;
  uint80 constant private ROUND_MAX = 2**80-1;

  uint40 internal latestEpochAndRound;
  uint80 internal latestRoundId;
  bytes16 public configDigest;
  mapping(uint80 => Round) internal rounds;
  mapping(address => Oracle) private oracles;
  address[] private oracleAddresses;

  address public operator;

  event OraclePermissionsUpdated(
    address indexed oracle,
    bool indexed whitelisted
  );
  event SubmissionReceived(
    int256 indexed submission,
    uint80 indexed round,
    address indexed oracle
  );
  event OperatorSet(address indexed operator);

  constructor(
    uint8 _decimals,
    string memory _description
  ) public {
    dcls = _decimals;
    desc = _description;
    setOperator(msg.sender);
  }

  function decimals() external override view returns (uint8) {
    AggregatorV3Interface aggr = aggregator;
    if (address(aggr) != address(0)) {
      return aggr.decimals();
    }
    return dcls;
  }

  function description() external override view returns (string memory) {
    AggregatorV3Interface aggr = aggregator;
    if (address(aggr) != address(0)) {
      return aggr.description();
    }
    return desc;
  }

  function version() external override view returns (uint256) {
    AggregatorV3Interface aggr = aggregator;
    if (address(aggr) != address(0)) {
      return aggr.version();
    }
    return 4;
  }

  function setOperator(address _operator) public onlyOwner {
    operator = _operator;
    emit OperatorSet(_operator);
  }

  function setConfigDigest(bytes16 digest) external onlyOwner {
    configDigest = digest;
  }

  function setAggregator(AggregatorV3Interface _aggregator) external onlyOwner {
    aggregator = _aggregator;
    owner = address(0);
    pendingOwner = address(0);
    emit OwnershipTransferred(address(0), msg.sender);
  }

  function changeOracles(
    address[] calldata _removed,
    address[] calldata _added,
    Role[] calldata _roles
  )
    external
    onlyOwner()
  {
    for (uint256 i = 0; i < _removed.length; i++) {
      removeOracle(_removed[i]);
    }
    require(uint256(oracleCount()).add(_added.length) <= MAX_ORACLE_COUNT, "max oracles allowed");
    require(_added.length == _roles.length, "length of roles is different from added");
    for (uint256 i = 0; i < _added.length; i++) {
      addOracle(_added[i], _roles[i]);
    }
  }

  /**
   * @notice called by oracles when they have witnessed a need to update
   * @param _roundId is the ID of the round this submission pertains to
   * @param _timestamp is the block timestamp of the round
   * @param _report is the observations
   * @param _rs is the r of oracles
   * @param _ss is the s of oracles
   * @param _rawVs is the v of oracles
   */
  function submit(
    uint256 _roundId,
    uint256 _timestamp,
    bytes calldata _report,
    bytes32[] calldata _rs, bytes32[] calldata _ss, bytes32 _rawVs
  )
    external
  {
    require(operator == msg.sender, "not an operator");
    require(_rs.length == _ss.length, "signatures out of registration");
    require(_rs.length <= MAX_ORACLE_COUNT, "too many signatures");
    uint80 rid = uint80(_roundId);
    require(_roundId < ROUND_MAX && rid == latestRoundId + 1, "invalid round id");
    {
      bytes32 h = keccak256(_report);
      bool[MAX_ORACLE_COUNT] memory signed;
      Oracle memory oracle;
      for (uint i = 0; i < _rs.length; i++) {
        address signer = ecrecover(h, uint8(_rawVs[i])+27, _rs[i], _ss[i]);
        oracle = oracles[signer];
        require(oracle.role != Role.Signer, "not an active oracle");
        require(!signed[oracle.index], "non-unique signature");
        signed[oracle.index] = true;
      }
    }
    (bytes32 rawReportContext, bytes32 rawObservers, int192[] memory observations) = abi.decode(_report, (bytes32, bytes32, int192[]));
    require(bytes16(rawReportContext << 88) == configDigest, "config digest mismatch");
    uint40 epochAndRound = uint40(uint256(rawReportContext));
    require(latestEpochAndRound < epochAndRound, "stale report");
    bytes memory observers = new bytes(observations.length);
    {
      bool[MAX_ORACLE_COUNT] memory seen;
      for (uint8 i = 0; i < observations.length; i++) {
        uint8 observerIdx = uint8(rawObservers[i]);
        require(!seen[observerIdx], "duplicate observer index");
        seen[observerIdx] = true;
        observers[i] = rawObservers[i];
      }
    }
    for (uint8 i = 0; i < observations.length - 1; i++) {
      bool inOrder = observations[i] <= observations[i+1];
      require(inOrder, "observations not sorted");
    }
    int192 median = observations[observations.length/2];
    rounds[rid].answer = median;
    rounds[rid].startedAt = _timestamp;
    rounds[rid].updatedAt = _timestamp;
    rounds[rid].answeredInRound = rid;
    latestRoundId = rid;
    latestEpochAndRound = epochAndRound;
  }

  function oracleCount() public view returns (uint8) {
    return uint8(oracleAddresses.length);
  }

  function getOracles() external view returns (address[] memory) {
    return oracleAddresses;
  }

  function getRoundData(uint80 _roundId)
    public
    view
    virtual
    override
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    )
  {
    AggregatorV3Interface aggr = aggregator;
    if (address(aggr) != address(0)) {
      return aggr.getRoundData(_roundId);
    }
    Round memory r = rounds[uint64(_roundId)];

    require(r.answeredInRound > 0 && _roundId <= ROUND_MAX, "No data present");

    return (
      _roundId,
      r.answer,
      r.startedAt,
      r.updatedAt,
      r.answeredInRound
    );
  }

  function latestRoundData()
    public
    view
    virtual
    override
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    )
  {
    AggregatorV3Interface aggr = aggregator;
    if (address(aggr) != address(0)) {
      return aggr.latestRoundData();
    }
    return getRoundData(latestRoundId);
  }

  function addOracle(address _oracle, Role role) private {
    require(oracles[_oracle].role == Role.Unset, "oracle already has been set");

    oracles[_oracle].role = role;
    oracles[_oracle].index = uint16(oracleAddresses.length);
    oracleAddresses.push(_oracle);

    emit OraclePermissionsUpdated(_oracle, true);
  }

  function removeOracle(address _oracle) private {
    require(oracles[_oracle].role != Role.Unset, "oracle is not set");

    address tail = oracleAddresses[uint256(oracleCount()).sub(1)];
    uint16 index = oracles[_oracle].index;
    oracles[_oracle].role = Role.Unset;
    oracles[tail].index = index;
    delete oracles[_oracle].index;
    oracleAddresses[index] = tail;
    oracleAddresses.pop();

    emit OraclePermissionsUpdated(_oracle, false);
  }
}
