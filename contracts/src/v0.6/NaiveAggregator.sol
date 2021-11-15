// SPDX-License-Identifier: MIT
pragma solidity 0.6.6;

import "./vendor/Ownable.sol";
import "./interfaces/AggregatorV3Interface.sol";
import "./vendor/SafeMathChainlink.sol";

contract NaiveAggregator is AggregatorV3Interface, Ownable {
  using SafeMathChainlink for uint256;

  struct Round {
    int256 answer;
    uint256 startedAt;
    uint256 updatedAt;
    uint80 answeredInRound;
  }

  event OperatorSet(address indexed operator, uint256 expireHeight);

  AggregatorV3Interface public aggregator;
  mapping(address => uint256) public operators;

  uint8 private dcls;
  string private desc;

  uint256 constant private MAX_ORACLE_COUNT = 31;
  uint80 constant private ROUND_MAX = 2**80-1;

  uint80 public latestRoundId;
  uint64 public latestRoundTimestamp;
  mapping(uint80 => Round) internal rounds;

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
    return 4;
  }

  function setOperator(address _operator, uint256 _expireHeight) external onlyOwner {
    operators[_operator] = _expireHeight;
    emit OperatorSet(_operator, _expireHeight);
  }

  function setAggregator(AggregatorV3Interface _aggregator) external onlyOwner {
    aggregator = _aggregator;
  }

  /**
   * @notice called by oracles when they have witnessed a need to update
   * @param _answer is the answer
   */
  function submit(int256 _answer, uint64 _timestamp) external {
    require(operators[msg.sender] > block.number, "no permission");
    require(_timestamp < block.timestamp && _timestamp > latestRoundTimestamp, "stale answer");
    uint80 rid = latestRoundId + 1;
    rounds[rid].answer = _answer;
    rounds[rid].startedAt = block.timestamp;
    rounds[rid].updatedAt = block.timestamp;
    rounds[rid].answeredInRound = rid;
    latestRoundId = rid;
    latestRoundTimestamp = _timestamp;
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
