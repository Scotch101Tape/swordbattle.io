class Session {
  constructor(configure) {
    this.maxCoins = configure.maxCoins;
    this.maxChests = configure.maxChests;
    this.maxAiPlayers = configure.maxAiPlayers;
    this.maxPlayers = configure.maxPlayers;

    this.coins = [];
    this.chests = [];
  }
}

module.exports = Session;