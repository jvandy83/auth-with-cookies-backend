dotenv.config();

import express from 'express';
import cookieParser from 'cookie-parser';

import argon from 'argon2';

import User from './models/User.js';

import mongoose from 'mongoose';

import cors from 'cors';

import dotenv from 'dotenv';

import {
	createAccessToken,
	createRefreshToken,
	sendRefreshToken,
	verifyRefreshToken,
} from './util/auth.js';

import { checkAuth } from './middleware/auth.js';

const app = express();

app.use(cookieParser());

app.use(express.json());

app.use(
	cors({
		credentials: true,
		origin: 'http://localhost:5000',
	}),
);

app.post('/login', async (req, res) => {
	const user = await User.findOne({ email: req.body.email });
	if (!user) {
		return res.status(422).json({
			error: {
				message: 'Username or password is invalid',
			},
		});
	}

	const isValid = await argon.verify(user.password, req.body.password);

	if (!isValid) {
		return res.status(422).json({
			error: {
				message: 'Username or password is invalid',
			},
		});
	}

	sendRefreshToken(res, createRefreshToken(user));
	console.log(createAccessToken(user));

	return res.json({
		ok: true,
		user,
		token: createAccessToken(user),
	});
});

app.post('/signup', async (req, res) => {
	let user = await User.findOne({ email: req.body.email });
	if (user) {
		return res.status(422).json({
			error: {
				message: 'Email is already in use',
			},
		});
	}
	// const user = new User(req.body);
	const hash = await argon.hash(req.body.password);
	user = await new User({ ...req.body, password: hash });
	await user.save();
	return res.status(200).json({
		ok: true,
	});
});

app.post('/add-profile', checkAuth, async (req, res) => {
	const userDoc = await User.findById(req.user);
	if (!userDoc) {
		return res.status(401).json({
			error: {
				message: 'User not found',
			},
		});
	}
	userDoc.firstName = req.body.firstName;
	userDoc.lastName = req.body.lastName;
	const user = await userDoc.save();
	return res.status(200).json({
		ok: true,
		user,
	});
});

app.post('/logout', (req, res) => {
	res.cookie('refresh_token', '', {
		httpOnly: true,
		maxAge: new Date(0),
	});
	return res.status(200).json({
		message: 'Logged out',
		accessToken: '',
	});
});

app.get('/me', checkAuth, async (req, res) => {
	console.log(req.user);
	const user = await User.findById(req.user);
	if (!user) {
		return res.status(401).json({
			ok: false,
		});
	}

	return res.status(200).json({
		ok: true,
		user,
		token: createAccessToken(user),
	});
});

app.get('/refresh-token', async (req, res) => {
	const refreshToken = req.cookies['refresh_token'];

	if (!refreshToken) {
		return res.status(401).json({
			token: '',
			error: {
				message: 'refreshToken not present in request',
			},
		});
	}

	let payload;

	try {
		// payload = { id: user._id }
		payload = verifyRefreshToken(refreshToken);
		console.log(payload);
	} catch (err) {
		res.json({
			token: '',
			user: '',
			isAuthenticated: false,
			error: {
				message: 'refreshToken payload not valid',
			},
		});
	}

	const user = await User.findById(payload.id);

	if (!user) {
		res.status(401).json({
			error: {
				message: 'User not found',
			},
			token: '',
			user: '',
			isAuthenticated: false,
		});
	}

	// - check tokenVersion in mongoDB
	// 	against current cookie token version
	// - if version has been incremented
	// 	we intentionally logged out
	// 	user due to account being hacked
	// 	or some other deliberate reason

	if (user.tokenVersion !== payload.tokenVersion) {
		return res.status(401).json({
			token: '',
			user: '',
			isAuthenticated: false,
			error: {
				message: 'token version is not valid',
			},
		});
	}

	// we have a valid token
	// send back new REFRESH_TOKEN value

	sendRefreshToken(res, createRefreshToken(user));

	// send back a new ACCESS_TOKEN value

	return res.status(200).json({
		message: 'Success',
		token: createAccessToken(user),
		user,
		isAuthenticated: true,
	});
});

mongoose
	.connect(
		'mongodb+srv://jared123:jared123@vanthedev.k2rxc.mongodb.net/auth-practice?retryWrites=true&w=majority',
	)
	.then(() => {
		app.listen(5000, () => {
			console.log('App listening on port 5000');
		});
	})
	.catch((err) => {
		console.log(err);
	});

/*

	export const fetchRefreshToken = async (req, res, next) => {
	const refreshToken = req.cookies['refresh_token'];

	if (!refreshToken) {
		return res.status(401).json({
			accessToken: '',
			message: 'refreshToken not present in request',
		});
	}

	let payload;

	try {
		// payload = { user: user._id }
		payload = verifyToken(refreshToken);
	} catch (err) {
		console.error(err);

		res.json({
			error: err,
			accessToken: '',
			message: 'refreshToken payload not valid',
		});
	}

	const user = await User.findById(payload.user);

	if (!user) {
		res.status(401).json({
			message: 'User not found',
			accessToken: '',
		});
	}

	- check tokenVersion in mongoDB
		against current cookie token version
	- if version has been incremented
		we intentionally logged out
		user due to account being hacked
		or some other deliberate reason

	if (user.tokenVersion !== payload.tokenVersion) {
		return res.status(401).json({
			accessToken: '',
			message: 'token version is not valid',
		});
	}

	// we have a valid token
	// send back new REFRESH_TOKEN value

	sendRefreshToken(res, createRefreshToken(user));

	// send back a new ACCESS_TOKEN value

	return res.status(200).json({
		message: 'Success',
		token: createAccessToken(user),
		user,
	});
};

export const logout = (req, res, next) => {
	// sendRefreshToken(res, createRefreshToken(user));
	console.log('inside logout controller');
	res.cookie('refresh_token', '', {
		httpOnly: true,
		maxAge: new Date(0),
	});
	return res.status(200).json({
		message: 'Logged out',
		accessToken: '',
	});
};

export const revokeRefreshToken = async (req, res, next) => {
	console.log(req.headers);
	let doc;
	try {
		doc = await User.findOneAndUpdate(
			{ _id: req.user },
			{ $inc: { tokenVersion: 1 } },
			{ new: true },
		);
	} catch (err) {
		console.error(err);
		res.status(500).json({
			message: 'Server Error',
		});
	}
	return res.status(200).json({
		message: 'User has been logged out',
	});
};

*/
