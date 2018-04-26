'use strict';
/* globals module, require */

var Users = require.main.require('./src/user'),
	Messaging = require.main.require('./src/messaging'),
	apiMiddleware = require('./middleware'),
	errorHandler = require('../../lib/errorHandler'),
	auth = require('../../lib/auth'),
	utils = require('./utils'),
	async = require.main.require('async');


module.exports = function(/*middleware*/) {
	var app = require('express').Router();

	app.post('/', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!utils.checkRequired(['username'], req, res)) {
			return false;
		}

		Users.create(req.body, function(err, uid) {
			return errorHandler.handle(err, res, {
				uid: uid
			});
		});
	});

	app.post('/chats/create', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!utils.checkRequired(['uid', 'toUid'], req, res)) {
			return false;
		}

		Messaging.newRoom(req.body.uid, [req.body.toUid], function(err, id) {
			return errorHandler.handle(err, res, {
				roomId: id
			});
		});
	});

	app.post('/chatRoom/enter', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!utils.checkRequired(['uid', 'toUid', 'roomId'], req, res)) {
			return false;
		}

		Messaging.addUsersToRoom(req.body.uid, [req.body.toUid], req.body.roomId, function(err, success) {
			return errorHandler.handle(err, res, {
				success: success
			});
		});
	});

	app.post('/chatRoom/leave', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!utils.checkRequired(['uid', 'toUid', 'roomId'], req, res)) {
			return false;
		}

		Messaging.removeUsersFromRoom(req.body.uid, [req.body.toUid], req.body.roomId, function(err, success) {
			return errorHandler.handle(err, res, {
				success: success
			});
		});
	});

	app.get('/chatRoom/getUser', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!req.query.roomId) {
			return false;
		}

		Messaging.getUidsInRoom(req.query.roomId, 0, -1, function(err, uids) {
			return errorHandler.handle(err, res, {
				uids: uids
			});
		});
	});

	app.get('/chatRoom/messages', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!req.query.roomId || !req.query.uid) {
			return false;
		}

		Messaging.getMessages({
			roomId: req.query.roomId,
			uid: req.query.uid,
			start: req.query.start || 0,
			stop: req.query.stop || -1,
			callerUid: req.query.uid
		}, function(err, messages) {
			return errorHandler.handle(err, res, {
				messages: messages
			});
		});
	});

	app.post('/chatRoom/message/send', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!utils.checkRequired(['message', 'fromuid', 'roomId'], req, res)) {
			return false;
		}

		var timestamp = Date.now();

		Messaging.addMessage(req.body.fromuid, req.body.roomId, req.body.message, timestamp, function(err, result) {
			return errorHandler.handle(err, res, {
				result: result
			});
		});
	});

	app.get('/chatRoom/unread/count', apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
		if (!req.query.userId) {
			return false;
		}

		Messaging.getUnreadCount(req.query.userId, function(err, count) {
			return errorHandler.handle(err, res, {
				count: count
			});
		});
	});

	app.route('/:uid')
		.put(apiMiddleware.requireUser, apiMiddleware.exposeAdmin, function(req, res) {
			if (parseInt(req.params.uid, 10) !== parseInt(req.user.uid, 10) && !res.locals.isAdmin) {
				return errorHandler.respond(401, res);
			}

			// `uid` in `updateProfile` refers to calling user, not target user
			req.body.uid = req.params.uid;

			Users.updateProfile(req.user.uid, req.body, function(err) {
				return errorHandler.handle(err, res);
			});
		})
		.delete(apiMiddleware.requireUser, apiMiddleware.exposeAdmin, function(req, res) {
			if (parseInt(req.params.uid, 10) !== parseInt(req.user.uid, 10) && !res.locals.isAdmin) {
				return errorHandler.respond(401, res);
			}

			// Clear out any user tokens belonging to the to-be-deleted user
			async.waterfall([
				async.apply(auth.getTokens, req.params.uid),
				function(tokens, next) {
					async.each(tokens, function(token, next) {
						auth.revokeToken(token, 'user', next);
					}, next);
				},
				async.apply(Users.delete, req.user.uid, req.params.uid)
			], function(err) {
				return errorHandler.handle(err, res);
			});
		});

	app.put('/:uid/password', apiMiddleware.requireUser, apiMiddleware.exposeAdmin, function(req, res) {
		if (parseInt(req.params.uid, 10) !== parseInt(req.user.uid, 10) && !res.locals.isAdmin) {
			return errorHandler.respond(401, res);
		}

		Users.changePassword(req.user.uid, {
			uid: req.params.uid,
			currentPassword: req.body.current || '',
			newPassword: req.body['new'] || ''
		}, function(err) {
			errorHandler.handle(err, res);
		});
	});

	app.put('/:uid/follow', apiMiddleware.requireUser, function(req, res) {
		Users.follow(req.user.uid, req.params.uid, function(err) {
			return errorHandler.handle(err, res);
		});
	});

	app.delete('/:uid/follow', apiMiddleware.requireUser, function(req, res) {
		Users.unfollow(req.user.uid, req.params.uid, function(err) {
			return errorHandler.handle(err, res);
		});
	});

	app.route('/:uid/chats')
		.post(apiMiddleware.requireUser, function(req, res) {
			if (!utils.checkRequired(['message'], req, res)) {
				return false;
			}

			var timestamp = parseInt(req.body.timestamp, 10) || Date.now();

			function addMessage(roomId) {
				Messaging.addMessage(req.user.uid, roomId, req.body.message, timestamp, function(err, message) {
					if (parseInt(req.body.quiet, 10) !== 1) {
						Messaging.notifyUsersInRoom(req.user.uid, roomId, message);
					}

					return errorHandler.handle(err, res, message);
				});
			}

			Messaging.canMessageUser(req.user.uid, req.params.uid, function(err) {
				if (err) {
					return errorHandler.handle(err, res);
				}

				if (req.body.roomId) {
					addMessage(req.body.roomId);
				} else {
					Messaging.newRoom(req.user.uid, [req.params.uid], function(err, roomId) {
						if (err) {
							return errorHandler.handle(err, res);
						}

						addMessage(roomId);
					});
				}
			});
		});

	app.route('/:uid/ban')
		.put(apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
			Users.ban(req.params.uid, function(err) {
				errorHandler.handle(err, res);
			});
		})
		.delete(apiMiddleware.requireUser, apiMiddleware.requireAdmin, function(req, res) {
			Users.unban(req.params.uid, function(err) {
				errorHandler.handle(err, res);
			});
		});

	app.route('/:uid/tokens')
		.get(apiMiddleware.requireUser, function(req, res) {
			if (parseInt(req.params.uid, 10) !== parseInt(req.user.uid, 10)) {
				return errorHandler.respond(401, res);
			}

			auth.getTokens(req.params.uid, function(err, tokens) {
				return errorHandler.handle(err, res, {
					tokens: tokens
				});
			});
		})
		.post(apiMiddleware.requireUser, function(req, res) {
			if (parseInt(req.params.uid, 10) !== parseInt(req.user.uid)) {
				return errorHandler.respond(401, res);
			}

			auth.generateToken(req.params.uid, function(err, token) {
				return errorHandler.handle(err, res, {
					token: token
				});
			});
		});

	app.delete('/:uid/tokens/:token', apiMiddleware.requireUser, function(req, res) {
		if (parseInt(req.params.uid, 10) !== req.user.uid) {
			return errorHandler.respond(401, res);
		}

		auth.revokeToken(req.params.token, 'user', function(err) {
			errorHandler.handle(err, res);
		});
	});

	return app;
};
