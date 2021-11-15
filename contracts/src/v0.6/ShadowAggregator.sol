// SPDX-License-Identifier: MIT
pragma solidity 0.6.6;

import "./vendor/Ownable.sol";
import "./interfaces/AggregatorV3Interface.sol";
import "./vendor/SafeMathChainlink.sol";

/**
 * @title The Prepaid Aggregator contract
 * @notice Handles aggregating data pushed in from off-chain. Oracles' submissions are gathered in
 * rounds, with each round aggregating the submissions for each oracle into a
 * single answer. The latest aggregated answer is exposed as well as historical
 * answers and their updated at timestamp.
 */
contract ShadowAggregator is AggregatorV3Interface, Ownable {
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
  address public originAggregator;

  uint256 constant private MAX_ORACLE_COUNT = 31;
  uint80 constant private ROUND_MAX = 2**80-1;

  uint40 internal latestEpochAndRound;
  uint80 public latestRoundId;
  bytes16 public configDigest;
  uint32 public configCount;
  mapping(uint80 => Round) internal rounds;
  mapping(address => Oracle) public oracles;
  address[] private signers;
  address[] private transmitters;

  event SubmissionReceived(
    int256 indexed submission,
    uint80 indexed round,
    address indexed oracle
  );

  constructor(
    address _origin,
    uint8 _decimals,
    string memory _description
  ) public {
    originAggregator = _origin;
    dcls = _decimals;
    desc = _description;
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

  function setConfigCount(uint32 _count) external onlyOwner {
    configCount = _count;
  }

  function setAggregator(AggregatorV3Interface _aggregator) external onlyOwner {
    aggregator = _aggregator;
  }

  /**
   * @notice sets offchain reporting protocol configuration incl. participating oracles
   * @param _signers addresses with which oracles sign the reports
   * @param _transmitters addresses oracles use to transmit the reports
   * @param _threshold number of faulty oracles the system can tolerate
   * @param _encodedConfigVersion version number for offchainEncoding schema
   * @param _encoded encoded off-chain oracle configuration
   */
  function setConfig(
    address[] calldata _signers,
    address[] calldata _transmitters,
    uint8 _threshold,
    uint64 _encodedConfigVersion,
    bytes calldata _encoded
  )
    external
    onlyOwner()
  {
    while (signers.length != 0) { // remove any old signer/transmitter addresses
      uint lastIdx = signers.length - 1;
      address signer = signers[lastIdx];
      address transmitter = transmitters[lastIdx];
      delete oracles[signer];
      delete oracles[transmitter];
      signers.pop();
      transmitters.pop();
    }

    for (uint i = 0; i < _signers.length; i++) { // add new signer/transmitter addresses
      require(
        oracles[_signers[i]].role == Role.Unset,
        "repeated signer address"
      );
      oracles[_signers[i]] = Oracle(uint8(i), Role.Signer);
      require(
        oracles[_transmitters[i]].role == Role.Unset,
        "repeated transmitter address"
      );
      oracles[_transmitters[i]] = Oracle(uint8(i), Role.Transmitter);
      signers.push(_signers[i]);
      transmitters.push(_transmitters[i]);
    }
    configCount += 1;
    configDigest = configDigestFromConfigData(
      originAggregator,
      configCount,
      _signers,
      _transmitters,
      _threshold,
      _encodedConfigVersion,
      _encoded
    );
    latestEpochAndRound = 0;
  }

  function configDigestFromConfigData(
    address _contractAddress,
    uint64 _configCount,
    address[] memory _signers,
    address[] memory _transmitters,
    uint8 _threshold,
    uint64 _encodedConfigVersion,
    bytes memory _encodedConfig
  ) internal pure returns (bytes16) {
    return bytes16(keccak256(abi.encode(_contractAddress, _configCount,
      _signers, _transmitters, _threshold, _encodedConfigVersion, _encodedConfig
    )));
  }

  /**
   * @notice called by oracles when they have witnessed a need to update
   * @param _report is the observations
   * @param _rs is the r of oracles
   * @param _ss is the s of oracles
   * @param _rawVs is the v of oracles
   */
  function submit(
    bytes calldata _report,
    bytes32[] calldata _rs, bytes32[] calldata _ss, bytes32 _rawVs
  )
    external
  {
    require(_rs.length == _ss.length, "signatures out of registration");
    require(_rs.length <= MAX_ORACLE_COUNT, "too many signatures");
    {
      bytes32 h = keccak256(_report);
      bool[MAX_ORACLE_COUNT] memory signed;
      Oracle memory oracle;
      for (uint i = 0; i < _rs.length; i++) {
        address signer = ecrecover(h, uint8(_rawVs[i])+27, _rs[i], _ss[i]);
        oracle = oracles[signer];
        require(oracle.role == Role.Signer, "not an active oracle");
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
    uint80 rid = latestRoundId + 1;
    rounds[rid].answer = median;
    rounds[rid].startedAt = block.timestamp;
    rounds[rid].updatedAt = block.timestamp;
    rounds[rid].answeredInRound = rid;
    latestRoundId = rid;
    latestEpochAndRound = epochAndRound;
  }

  function oracleCount() public view returns (uint8) {
    return uint8(signers.length);
  }

  function getOracles() external view returns (address[] memory) {
    return signers;
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
}
