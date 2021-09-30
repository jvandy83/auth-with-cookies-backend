import jwt from 'jsonwebtoken';

import dotenv from 'dotenv';

dotenv.config();

const { ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET } = process.env;

export const createAccessToken = (user) =>
	jwt.sign({ id: user._id }, ACCESS_TOKEN_SECRET, { expiresIn: '15m' });

export const createRefreshToken = (user) => {
	return jwt.sign(
		{ id: user._id, tokenVersion: user.tokenVersion },
		REFRESH_TOKEN_SECRET,
		{ expiresIn: '7d' },
	);
};

export const sendRefreshToken = (res, token) => {
	return res.cookie('refresh_token', token, { httpOnly: true });
};

export const verifyRefreshToken = (token) => {
	return jwt.verify(token, REFRESH_TOKEN_SECRET);
};
