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

  struct Round {
    int256 answer;
    uint256 startedAt;
    uint256 updatedAt;
    uint80 answeredInRound;
  }

  struct OracleStatus {
    uint80 startingRound;
    uint80 endingRound;
    uint16 index;
  }

  AggregatorV3Interface public aggregator;

  uint8 private dcls;
  string private desc;

  uint256 constant private MAX_ORACLE_COUNT = 25;
  uint80 constant private ROUND_MAX = 2**80-1;

  uint80 internal latestRoundId;
  mapping(address => OracleStatus) private oracles;
  mapping(uint80 => Round) internal rounds;
  address[] private oracleAddresses;

  event AnswerUpdated(
    int256 indexed current,
    uint256 indexed roundId,
    uint256 updatedAt
  );
  event NewRound(
    uint256 indexed roundId,
    address indexed startedBy,
    uint256 startedAt
  );
  event OraclePermissionsUpdated(
    address indexed oracle,
    bool indexed whitelisted
  );
  event SubmissionReceived(
    int256 indexed submission,
    uint80 indexed round,
    address indexed oracle
  );

  constructor(
    uint8 _decimals,
    string memory _description
  ) public {
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
    return 3;
  }

  function setAggregator(AggregatorV3Interface _aggregator) external onlyOwner {
    aggregator = _aggregator;
    owner = address(0);
    pendingOwner = address(0);
    emit OwnershipTransferred(address(0), msg.sender);
  }

  function generateKey(
    uint256 _roundId,
    int256 _answer,
    uint256 _startedAt,
    uint256 _updatedAt,
    uint256 _answeredInRound
  ) public view returns(bytes32) {
    return keccak256(abi.encodePacked(address(this), _roundId, _answer, _startedAt, _updatedAt, _answeredInRound));
  }

  /**
   * @notice called by oracles when they have witnessed a need to update
   * @param _roundId is the ID of the round this submission pertains to
   * @param _answer is the answer of this round
   * @param _startedAt is the start timestamp of this round
   * @param _updatedAt is the update timestamp of this round
   * @param _answeredInRound is the round of the answer be set
   * @param _signatures is the signatures from oracles
   */
  function submit(
    uint256 _roundId,
    int256 _answer,
    uint256 _startedAt,
    uint256 _updatedAt,
    uint256 _answeredInRound,
    bytes calldata _signatures
  )
    external
  {
    require(_roundId < ROUND_MAX && _answeredInRound < ROUND_MAX, "invalid round id");
    uint80 rid = uint80(_roundId);
    require(rid == latestRoundId + 1, "invalid round id");
    require(verify(_roundId, _answer, _startedAt, _updatedAt, _answeredInRound, _signatures), "invalid signatures");
    rounds[rid].startedAt = _startedAt;

    emit NewRound(rid, msg.sender, rounds[rid].startedAt);

    rounds[rid].answer = _answer;
    rounds[rid].updatedAt = _updatedAt;
    rounds[rid].answeredInRound = uint80(_answeredInRound);
    latestRoundId = rid;

    emit AnswerUpdated(_answer, rid, now);
  }

  function changeOracles(
    address[] calldata _removed,
    address[] calldata _added
  )
    external
    onlyOwner()
  {
    for (uint256 i = 0; i < _removed.length; i++) {
      removeOracle(_removed[i]);
    }
    require(uint256(oracleCount()).add(_added.length) <= MAX_ORACLE_COUNT, "max oracles allowed");
    for (uint256 i = 0; i < _added.length; i++) {
      addOracle(_added[i]);
    }
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

  function verify(
    uint256 _roundId,
    int256 _answer,
    uint256 _startedAt,
    uint256 _updatedAt,
    uint256 _answeredInRound,
    bytes memory _signatures
  )
    private
    returns (bool)
  {
    uint80 rid = uint80(_roundId);
    bytes32 key = generateKey(_roundId, _answer, _startedAt, _updatedAt, _answeredInRound);
    uint256 numOfSignatures = _signatures.length / 65;
    address[] memory validators = new address[](numOfSignatures);
    for (uint256 i = 0; i < numOfSignatures; i++) {
        address oracle = recover(key, _signatures, i * 65);
        for (uint256 j = 0; j < i; j++) {
            require(oracle != validators[j], "duplicate oracle");
        }
        validators[i] = oracle;
        bytes memory err = validateOracleRound(oracle, rid);
        require(err.length == 0, string(err));

        emit SubmissionReceived(_answer, rid, oracle);
    }

    return validators.length * 3 > validators.length * 2;
  }

  function recover(
      bytes32 hash,
      bytes memory signature,
      uint256 offset
  ) internal pure returns (address) {
      bytes32 r;
      bytes32 s;
      uint8 v;

      // Divide the signature in r, s and v variables with inline assembly.

      // solium-disable-next-line security/no-inline-assembly
      assembly {
          r := mload(add(signature, add(offset, 0x20)))
          s := mload(add(signature, add(offset, 0x40)))
          v := byte(0, mload(add(signature, add(offset, 0x60))))
      }

      // Version of signature should be 27 or 28, but 0 and 1 are also possible versions
      if (v < 27) {
          v += 27;
      }

      // If the version is correct return the signer address
      if (v != 27 && v != 28) {
          return (address(0));
      }
      // solium-disable-next-line arg-overflow
      return ecrecover(hash, v, r, s);
  }

  function getStartingRound(address _oracle)
    private
    view
    returns (uint80)
  {
    uint80 currentRound = latestRoundId;
    if (currentRound != 0 && currentRound == oracles[_oracle].endingRound) {
      return currentRound;
    }
    return currentRound + 1;
  }

  function addOracle(address _oracle) private {
    require(!oracleEnabled(_oracle), "oracle already enabled");

    oracles[_oracle].startingRound = getStartingRound(_oracle);
    oracles[_oracle].endingRound = ROUND_MAX;
    oracles[_oracle].index = uint16(oracleAddresses.length);
    oracleAddresses.push(_oracle);

    emit OraclePermissionsUpdated(_oracle, true);
  }

  function removeOracle(address _oracle) private {
    require(oracleEnabled(_oracle), "oracle not enabled");

    oracles[_oracle].endingRound = latestRoundId + 1;
    address tail = oracleAddresses[uint256(oracleCount()).sub(1)];
    uint16 index = oracles[_oracle].index;
    oracles[tail].index = index;
    delete oracles[_oracle].index;
    oracleAddresses[index] = tail;
    oracleAddresses.pop();

    emit OraclePermissionsUpdated(_oracle, false);
  }

  function validateOracleRound(address _oracle, uint80 _roundId)
    private
    view
    returns (bytes memory)
  {
    // cache storage reads
    uint80 startingRound = oracles[_oracle].startingRound;

    if (startingRound == 0) return "not enabled oracle";
    if (startingRound > _roundId) return "not yet enabled oracle";
    if (oracles[_oracle].endingRound < _roundId) return "no longer allowed oracle";
  }

  function oracleEnabled(address _oracle)
    private
    view
    returns (bool)
  {
    return oracles[_oracle].endingRound == ROUND_MAX;
  }
}
