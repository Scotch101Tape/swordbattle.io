/*
SessionObject class
A class for instances that are used by the session
This allows for miminal changes to the code from how it was oringinally written with singletons to a more DRY and instance based paradigm
*/

class SessionObject {
  constructor(game) {
    this.game = game
  }
}

module.exports = SessionObject