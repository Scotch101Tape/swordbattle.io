/*
index.js
The main file for the server
This is the first file that is run
*/

/*
TODO 6/4/22
 - Player stuff (player class)
 - client stuff
 - you got this
*/

const express = require("express");
const https = require("https");
var http = require("http");
require("dotenv").config();
const { Server } = require("socket.io");
const app = express();
var emailValidator = require("email-validator");
const bcrypt = require("bcrypt");
var uuid = require("uuid");
var fs = require("fs");
var process = require("process");

// When the server is exiting and preping to shut down, this turns to "exiting"
var serverState = "running";

//var cors = require("cors");

// The servers
var server;
var httpsserver;

//console.log(fs.readFileSync("/etc/letsencrypt/live/test.swordbattle.io/fullchain.pem"))

// Encryption stuff
var usinghttps = false;
if (process.env.USEFISHYSSL === "true") {
  usinghttps = true;
  var options = {
    key: fs.readFileSync(
      "/etc/letsencrypt/live/us2.swordbattle.io/privkey.pem"
    ),
    cert: fs.readFileSync(
      "/etc/letsencrypt/live/us2.swordbattle.io/fullchain.pem"
    ),
  };
  httpsserver = https.createServer(options, app).listen(443);
}

// Set up the server
server = http.createServer(app);

//server = http.createServer(app);

// Modules, very messy but it works and is really not important to code structure so dont touch it
const axios = require("axios").default;
var filter = require("leo-profanity");
const moderation = require("./moderation");
const { v4: uuidv4 } = require("uuid");
const {recaptcha} = require("./config.json");
var passwordValidator = require("password-validator");
var schema = new passwordValidator();
app.use(express.json());
// Add properties to it
schema
  .is()
  .min(5, "Password has to be at least 5 chars") // Minimum length 5
  .is()
  .max(20, "Password cant be longer than 20 chars") // Maximum length 20
  .has()
  .not()
  .spaces(undefined, "Password cant contain spaces"); // Should not have spaces

// Modules
const Player = require("./classes/Player");
const Coin = require("./classes/Coin");
const Chest = require("./classes/Chest");
const AiPlayer = require("./classes/AiPlayer");
const PlayerList = require("./classes/Players");
const Session = require("./classes/Session");
const evolutions = require("./classes/evolutions");
const Sessions = require("./classes/Sessions");
const { sql } = require("./database");
const { config } = require("dotenv");

// Contains info on cosmetics
const cosmetics = JSON.parse(fs.readFileSync("./cosmetics.json"));

// Sanity checks for when password and username are passed in a http request
const checkifMissingFields = (req,res,next) => {
  if(typeof req.body!=="object" || typeof req.body.password !== "string" || typeof req.body.username !== "string" || typeof req.body.captcha !== "string") {	
      res.send({error: "Missing fields"});
      return;
  }
  next();
};

// Set up socket.io
const io = new Server(usinghttps ? httpsserver : server, {
  cors: { origin: "*" },
});

// Utility function
function getRandomInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

// If it is in production, then use rate limiter
var production = true;
if (production) {
	const rateLimit = require("express-rate-limit");
	const limiter = rateLimit({
		windowMs: 60 * 1000, // 1 min
		max: 300, // limit each IP to 52 requests per min 
	});
	app.use(limiter);
}

// Idk, something, not sure, dont touch
app.set("trust proxy", true);
/*
app.use((req, res, next) => {
  console.log("URL:", req.url);
  console.log("IP:", req.ip);
  next();
});*/


moderation.start(app, io);

app.use(function (req, res, next) {
  // Website you wish to allow to connect
  res.setHeader("Access-Control-Allow-Origin", "*");

  // Request methods you wish to allow
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE"
  );

  // Request headers you wish to allow
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-Requested-With,content-type"
  );

  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader("Access-Control-Allow-Credentials", true);

  // Pass to next layer of middleware
  next();
});

/*******************************************************************************************************/
/* App paths *******************************************************************************************/
/*******************************************************************************************************/

// / leads to dist directory
app.use("/", express.static("dist"));

// /assets leads to assets directory
app.use("/assets", express.static("assets"));

// /api/buy allows for buying cosmetic
app.post("/api/buy", async (req, res) => {
  //read cosmetics.json
  var cosmetics = JSON.parse(fs.readFileSync("./cosmetics.json"));

  //get user data
  var secret = req.body.secret;
  var item = req.body.item;

  // Santiy check for if they sent an item
  if (!item || item == "undefined") {
    res.status(400).send("No item specified");
    return;
  }

  // Try to find item in the cosmetics
  var item = cosmetics.skins.find((e) => e.name == item);

  // Santiy check for if the item exists
  if (!item) {
    res.status(400).send("Item not found");
    return;
  }

  var acc;
  // Make sure the secret exists
  if (secret && secret != "undefined") {
    // Get the account
    var account = await sql`select skins,coins,username from accounts where secret=${secret}`;

    // Make sure account exists
    if (account[0]) {
      acc = account[0];
      var yo =
        await sql`SELECT sum(coins) FROM games WHERE lower(name)=${acc.username.toLowerCase()} AND verified='true';`;
      acc.bal = yo[0].sum + acc.coins;

      // Check if the item is already bought
      if (acc.skins.collected.includes(item.name)) {
        res.status(400).send("Skin already owned");
        return;
      }

      // Check if the item is too many coins for the player trying to buy it
      if (acc.bal < item.price) {
        res.status(406).send("Not enough coins");
        return;
      }

      // Update the balence and skins of the player
      var newbal = acc.coins - item.price;
      var newskins = acc.skins;
      newskins.collected.push(item.name);

      // Update the database
      await sql`UPDATE accounts SET skins=${JSON.stringify(
        newskins
      )},coins=${newbal} WHERE secret=${secret}`;

      // Send a sucess back
      res.send("Success");
      return;
    } else {
      // Error for bad secret
      res.status(400).send("Invalid secret");
      return;
    }
  } else {
    // Error for no secret
    res.status(400).send("No secret provided");
    return;
  }
});

// /api/equip allows for equiping a skin
app.post("/api/equip", async (req, res) => {
  // get data from request
  var secret = req.body.secret;
  var item = req.body.item;

  // Sanity check for if the item was sent
  if (!item || item == "undefined") {
    res.status(400).send("No item specified");
    return;
  }
  
  // Trying to find the item specified
  var item = cosmetics.skins.find((e) => e.name == item);

  // Sanity check for if the item exists
  if (!item) {
    res.status(400).send("Item not found");
    return;
  }

  var acc;
  // Make sure secret was sent
  if (secret && secret != "undefined") {
    // Get the account associated with the secret
    var account = await sql`select skins,coins,username from accounts where secret=${secret}`;

    // Make sure the account exists
    if (account[0]) {
      acc = account[0];
      // Make sure the player owns the skin
      if (acc.skins.collected.includes(item.name)) {
        // Update which skin is equipped
        var newskins = acc.skins;
        newskins.selected = item.name;

        // Updata database
        await sql`UPDATE accounts SET skins=${JSON.stringify(
          newskins
        )} WHERE secret=${secret}`;

        // Return success
        res.send("Success");
        return;
      } else {
        // Error if the item is not owned
        res.status(400).send("Item not owned");
        return;
      }
    } else {
      // Error if the secret is bad
      res.status(400).send("Invalid secret");
      return;
    }
  } else {
    // Error if no secret
    res.status(400).send("No secret provided");
    return;
  }
});

// /api/signup allows for players to sign up
// the checkifMissingFields middleware runs sanity checks to make sure that the correct information is in the body
app.post("/api/signup",checkifMissingFields, async (req, res) => {
  // Seems redundant as checkifMissingFields just did this, though I will not mess with it
	if(typeof req.body!=="object" || typeof req.body.password !== "string" || typeof req.body.username !== "string") {	
		res.send({error: "Missing fields"});
		return;
	}

  // Make sure the email is valid
	if(req.body.email && req.body.email.length > 30) {
		res.send({error: "Email too long"});
		return;
	}
	if(req.body.email && !emailValidator.validate(req.body.email)) {
		res.send({error: "Invalid email"});
		return;
	}

  // Make sure the password is valid
	if(!schema.validate(req.body.password)) {
		res.send({error:schema.validate(req.body.password, { details: true })[0].message});
		return;
	}
  
  // Make sure the username is valid
	var username = req.body.username;
	if(username.length >= 20) {
		res.send({error: "Username has to be shorter than 20 characters"});
		return;
	}
	if(username.charAt(0) == " " || username.charAt(username.length - 1) == " ") {
		res.send({error: "Username can't start or end with a space"});
		return;
	}
	if(username.includes("  ")) {
		res.send({error: "Username can't have two spaces in a row"});
		return;
	}
	var regex = /^[a-zA-Z0-9!@"$%&:';()*\+,;\-=[\]\^_{|}<>~` ]+$/g;
	if(!username.match(regex)) {
		res.send({error: "Username can only contain letters, numbers, spaces, and the following symbols: !@\"$%&:';()*\+,-=[\]\^_{|}<>~`"});
		return;
	}
	var containsProfanity = filter.check(username);
	if(containsProfanity) {
		res.send({error: "Username contains a bad word!\nIf this is a mistake, please contact an admin."});
		return;
	}
	var exists = await sql`select exists(select 1 from accounts where lower(username)=lower(${username}))`;
	if (exists[0].exists) {
		res.send({error: "Username already taken"});
		return;
	}

  // Encrpyt the username and password and put it into the database
	bcrypt.hash(req.body.password, 10, (err, hash) => {
		if (err) {
      // Send error if anything fails
			res.status(500).send({error:"Internal server error"});
			return;
		}

    // Create a secret for the account
		var secret = uuid.v4();

    // Update the database
		sql`insert into accounts(username, password, email, secret, skins, lastlogin) values(${username}, ${hash}, ${req.body.email}, ${secret}, ${JSON.stringify({collected: ["player"], selected: "player"})}, ${Date.now()})`;

    // Send the secret back
		res.send({secret: secret});
	});
});

app.post("/api/login",checkifMissingFields, async (req, res) => { 


	async function doit() {
	var username = req.body.username;
	var password = req.body.password;
	var account = await sql`select * from accounts where lower(username)=lower(${username})`;

	if(!account[0]) {
		res.send({error: "Invalid username"});
		return;
	}

	const match = await bcrypt.compare(password, account[0].password);
	if(!match) {
		res.send({error: "Invalid password"});
		return;
	}
	
	res.send(account[0]);
	}
	var send = {
		secret: process.env.CAPTCHASECRET,
		response: req.body.captcha,
		remoteip: req.headers["x-forwarded-for"] || req.socket.remoteAddress 
	};
	if(recaptcha) {
		axios
			.post(
				"https://www.google.com/recaptcha/api/siteverify?" +
	  new URLSearchParams(send)
			)
			.then(async (f) => {
				f = f.data;
				if (!f.success) {
					res.status(403).send("Captcha failed " +  f["error-codes"].toString());
					return;
				}
				if (f.score < 0.3) {
					res.status(403).send("Captcha score too low");
					return;
				}
				doit();
			});
	}else doit();
});

app.post("/api/loginsecret", async (req, res) => {
  if (!req.body || !req.body.secret || req.body.captcha == undefined) {
    res.send({ error: "Missing secret or captcha" });
    return;
  }

  async function doit() {
    var secret = req.body.secret;

    var account = await sql`select * from accounts where secret=${secret}`;

    if (!account[0]) {
      res.send({ error: "Invalid secret" });
      return;
    }

    res.send(account[0]);
  }
  var send = {
    secret: process.env.CAPTCHASECRET,
    response: req.body.captcha,
    remoteip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
  };
  if (recaptcha) {
    axios
      .post(
        "https://www.google.com/recaptcha/api/siteverify?" +
          new URLSearchParams(send)
      )
      .then(async (f) => {
        f = f.data;
        if (!f.success) {
          res.status(403).send("Captcha failed " + f["error-codes"].toString());
          return;
        }
        if (f.score < 0.3) {
          res.status(403).send("Captcha score too low");
          return;
        }
        doit();
      });
  } else doit();
});

app.get("/skins", async (req, res) => {
  res.redirect("/shop");
});

app.get("/shop", async (req, res) => {
  //get user data
  var secret = req.query.secret;
  var acc;
  if (secret != "undefined") {
    var account =
      await sql`select skins,coins,username from accounts where secret=${secret}`;
    if (account[0]) {
      acc = account[0];
      var yo =
        await sql`SELECT sum(coins) FROM games WHERE lower(name)=${acc.username.toLowerCase()} AND verified='true';`;
      acc.bal = yo[0].sum + acc.coins;
    }
  }

  res.render("shop.ejs", {
    cosmetics: cosmetics,
    account: acc,
    secret: secret,
  });
});

app.get("/leaderboard", async (req, res) => {
  //SELECT * from games where EXTRACT(EPOCH FROM (now() - created_at)) < 86400 ORDER BY coins DESC LIMIT 10

  //var lb= await sql`SELECT * FROM games ORDER BY coins DESC LIMIT 13`;
  var type = ["coins", "kills", "time", "xp"].includes(req.query.type)
    ? req.query.type
    : "coins";
  var duration = ["all", "day", "week", "xp"].includes(req.query.duration)
    ? req.query.duration
    : "all";
  if (type !== "xp") {
    if (duration != "all") {
      var lb =
        await sql`SELECT * from games where EXTRACT(EPOCH FROM (now() - created_at)) < ${
          duration == "day" ? "86400" : "608400"
        } ORDER BY ${sql(type)} DESC, created_at DESC LIMIT 23`;
    } else {
      var lb = await sql`SELECT * from games ORDER BY ${sql(
        type
      )} DESC, created_at DESC LIMIT 23`;
    }
  } else {
    if (duration != "all") {
      var lb =
        await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true and EXTRACT(EPOCH FROM (now() - created_at)) < ${
          duration == "day" ? "86400" : "608400"
        } group by name order by xp desc limit 23`;
    } else {
      var lb =
        await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true group by name order by xp desc limit 23`;
    }
    lb = lb.map((x) => {
      x.verified = true;
      return x;
    });
  }

  console.log(type, duration);
  res.render("leaderboard.ejs", { lb: lb, type: type, duration: duration });
});

app.get("/settings", async (req, res) => {
  res.send(
    "I'm still working on this page.<br><br>For now, if you want to change password, or change your username, please email me at<br>gautamgxtv@gmail.com"
  );
});

app.get("/:user", async (req, res, next) => {
  var user = req.params.user;
  var dbuser =
    await sql`SELECT * from accounts where lower(username)=lower(${user})`;
  if (!dbuser[0]) {
    next();
  } else {
    var yo =
      await sql`SELECT * FROM games WHERE lower(name)=${user.toLowerCase()} AND verified='true';`;

    /*
		TODO

		SELECT A.dt,
		B.NAME,
		B.COINS
		FROM
		(
		SELECT distinct(DATE_ACTUAL) as dt FROM d_date
			WHERE DATE_ACTUAL>='2022-01-01'
		order by date_actual asc
		) A
		
		LEFT outer JOIN 
		(
		SELECT
		NAME,
		CREATED_AT::DATE AS PLAYED_DATE,
		sum(COINS) as coins
		FROM
		GAMES GMS
		WHERE VERIFIED=TRUE
		group by name,created_at::Date
		) B
		ON A.dt=B.PLAYED_DATE
		WHERE NAME='Dooku'
		ORDER BY A.dt ASC
	
*/

    var stats = await sql`
		select a.dt,b.name,b.xp,b.kills from
		(
		select distinct(created_at::date) as Dt from games where created_at >= ${
      dbuser[0].created_at
    }::date-1 
		order by created_at::date 
		) a
		left join
		(
		  SELECT name,created_at::date as dt1,(sum(coins)+(sum(kills)*100)) as xp,sum(kills) as kills ,sum(coins) as coins,
		  sum(time) as time FROM games WHERE verified='true' and lower(name)=${user.toLowerCase()} group by name,created_at::date
		) b on a.dt=b.dt1 order by a.dt asc
		`;
    var lb =
      await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true group by name order by xp desc`;
    var lb2 =
      await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true and EXTRACT(EPOCH FROM (now() - created_at)) < 86400 group by name order by xp desc`;
    res.render("user.ejs", {
      user: dbuser[0],
      games: yo,
      stats: stats,
      lb: lb,
      lb2: lb2,
    });
  }
});

Object.filter = (obj, predicate) =>
  Object.keys(obj)
    .filter((key) => predicate(obj[key]))
    .reduce((res, key) => ((res[key] = obj[key]), res), {});

/*************************************************************************************************/
/* Socket Connections ****************************************************************************/
/*************************************************************************************************/

// Max number of players allowed to connect to server (arbitrary for now)
const MAX_TOTAL_PLAYERS = 1000;

// Create a new session of the game
var sessions = new Sessions(io);

// Allow moderation to refrence sessions
// This is very hacky but tbh I don't feel like messin with moderation.js
// It works 😁
moderation.sessions = sessions;

// When the socket connects
io.on("connection", async (socket) => {
  socket.joinTime = Date.now();
  socket.ip = socket.handshake.headers["x-forwarded-for"];

  // Check if the ip is banned
  if (moderation.bannedIps.includes(socket.ip)) {
    socket.emit(
      "ban",
      "You are banned. Appeal to gautamgxtv@gmail.com<br><br>BANNED IP: " +
        socket.ip
    );
    socket.disconnect();
  }

  // When the player wants to get into the game
  socket.on("go", async (r, captchatoken, tryverify, options) => {
    // If the server is exiting, then dont allow a player to join
    if (serverState == "exiting") {
      socket.emit(
        "ban",
        "<h1>Server is shutting down, we'll be right back!<br>Sorry for the inconvenience.<br><br></h1><hr>"
      );
      return socket.disconnect();
    }

    // When the sanity checks are passed, this function will run
    async function ready() {
      // Add socket to the session it belongs to
      const session = sessions.session(options.room);
      await session.connectSocket(socket, options);

      // Log to console
      console.log(`Socket ${socket.id} joined room ${options.room}`);
		}

    // If options not sent, set as empty object 
    if (options == undefined) {
      options = {};
    }

    // Add name to options
    options.name = r;

    // Add tryverify to options
    options.tryverify = tryverify;

    // Ban if captcha not sent
		if (!captchatoken && recaptcha) {
			socket.emit(
				"ban",
				"You were kicked for not sending a captchatoken. Send this message to gautamgxtv@gmail.com if you think this is a bug."
			);
			return socket.disconnect();
		}

    // Ban if not sent name
		if (!options.name) {
			socket.emit("ban", "You were kicked for not sending a name. ");
			return socket.disconnect();
		}

    // Ban if player is already connected
		if (socket.id in sessions.allSockets()) {
			socket.emit(
				"ban",
				"You were kicked for 2 players on 1 id. Send this message to gautamgxtv@gmail.com<br> In the meantime, try restarting your computer if this happens a lot. "
			);
			return socket.disconnect();
		}

    // If the room is undefined, assume it is the main room
    if (!("room" in options)) {
      options.room = Sessions.MAIN_ROOM;
    }

    // Ban if session they want to join does not exist
    // (currently there is no way to create new sessions, so this will ban if room is anything but [MAIN_ROOM_NAME])
    if (!sessions.has(options.room)) {
      socket.emit("ban", "Session you are trying to join does not exist");
      return socket.disconnect();
    }

    // Ban if session is full
		if (sessions.session(options.room).playerCount >= sessions.session(options.room).maxPlayers) {
			socket.emit("ban", "Session is full. Please try again later.");
			return socket.disconnect();
		}

    // Ban if too many players connected to server
    if (sessions.allPlayers().length >= MAX_TOTAL_PLAYERS) {
      socket.emit("ban", "Server is full. Please try again later");
      return socket.disconnect();
    }

    // Ban if the password for the session is incorrect
    if (options.room != Sessions.MAIN_ROOM) {
      if (Sessions.isCorrectPassword(options.room, options.password)) {
        socket.emit("ban", "Incorrect password for room");
      }
    }

    // Do the captcha
		var send = {
			secret: process.env.CAPTCHASECRET,
			response: captchatoken,
			remoteip: socket.ip,
		};

		if(recaptcha) {
			axios
				.post(
					"https://www.google.com/recaptcha/api/siteverify?" +
          new URLSearchParams(send)
				)
				.then((f) => {
					f = f.data;

          // Ban if error during captcha
					if (!f.success) {
						socket.emit(
							"ban",
							"Error while verifying captcha<br>" + f["error-codes"].toString()
						);
						socket.disconnect();
						return;
					}

          // Ban if captcha failed
					if (f.score < 0.3) {
						socket.emit(
							"ban",
							`Captcha score too low: ${f.score}<br><br>If you're using a vpn, disable it. <br>If your on incognito, go onto a normal window<br>If your not signed in to a google account, sign in<br><br>If none of these worked, contact gautamgxtv@gmail.com`
						);
						socket.disconnect();
						return;
					}

          // See the defination of ready function above
					ready();
				});
		} else {
      ready();
    }
	});

  // The ping socket connection :)
  socket.on( "ping", function ( fn ) {
    fn(); // Simply execute the callback on the client
  } );
});


/***********************************************/
/* Tick ****************************************/
/***********************************************/

// The last second that was surpassed, used for computing tps
var secondStart = Date.now();

// The counter for ticks per second
// increamented every time a tick runs
var tps = 0;

// The actual ticks per second, hold the last tps value that was valid
// (This is used because the tps variable is used for calculating the ticks per second)
var actps = 0;

// app/api/serverinfo leads to a json of stats
app.get("/api/serverinfo/:room", (req, res) => {
  // Get the session that corresponds with the room passed
  var session = sessions.session(req.params.room || Sessions.MAIN_ROOM);
  
  // Send the stats
  res.send({
    playerCount: session.totalPlayerCount(),
    lag: actps > 15 ? "No lag" : actps > 6 ? "Moderate lag" : "Extreme lag",
    maxPlayers: maxPlayers,
    tps: actps,
    realPlayerCount: session.realPlayerCount(),
    aiPlayerCount: session.aiPlayerCount()
  });
});

// TODO figure out what needs to go to tick
// TODO: fix player and ai player libs to work with session thing

// 30 times per second do this (1000 / 30 ms)
setInterval(async () => {
	//const used = process.memoryUsage().heapUsed / 1024 / 1024;
//console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`);

  // Set the mod io to io???? (idk why this is here)
	moderation.io = io;

	// If its been one second since lst calculating the tps
	if (Date.now() - secondStart >= 1000) {
    // Emit ticks per second
		io.sockets.emit("tps", tps);

    // Update the actual ticks per second varaible
		actps = tps;
		//console.log("Players: "+Object.keys(players).length+"\nTPS: "+tps+"\n")

    // Update when the tps was last calculated
		secondStart = Date.now();

    // Restart the tps counter
		tps = 0;
	}

  // Tick each session
  for (const session of sessions.sessionsInList()) {
    session.tick();
  }

  // Increment tps for calculation
	tps += 1;
}, 1000 / 30);

/***********************************************/
/* Technical Stuff 😨 *************************/
/***********************************************/

// Start the server and listen on the port in the .env
// If the port is not in the .env, then use 3000
server.listen(process.env.PORT || 3000, () => {
  console.log("server started");
});

// When the code is told to stop
process.on("SIGTERM", () => {
  // Do a clean exit
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch((e) => {
      console.log(e, "failed to exit cleanly");
      process.exit(1);
    });
});

// When ctrl-C is pressed in terminal
process.on("SIGINT", () => {
  // Do a clean exit
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch((e) => {
      console.log(e, "failed to exit cleanly");
      process.exit(1);
    });
});

// When there is a an unhandled rejection
process.on("unhandledRejection", (reason, p) => {
  console.log("Unhandled Rejection at: Promise", p, "\nreason:", reason);
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch(() => {
      console.log("failed to exit cleanly");
      process.exit(1);
    });
});

// Cleanly exit
async function cleanExit() {
  // TODO make this more efficient

  console.log("exiting cleanly...");

  // Set the server state to exiting
  // This will make it so players leaving are ignored
  serverState = "exiting";

  // Cleanup the sessions
  for (const session of sessions.sessionsInList()) {
    session.cleanup();
  }
}

/*
http.createServer(function (req, res) {
    res.writeHead(301, { "Location": "https://" + req.headers["host"] + req.url });
    res.end();
}).listen(80);
*/
