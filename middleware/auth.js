import jwt from 'jsonwebtoken';

import dotenv from 'dotenv';

dotenv.config();

export const checkAuth = async (req, res, next) => {
	console.log('REQ.HEADER IN MIDDLEWARE', req.headers.authorization);
	const token = req.headers.authorization.replace('Bearer ', '');
	console.log('PARSED TOKEN', token);
	if (!token) {
		return res.status(401).json({
			ok: false,
			message: 'User is not authorized',
		});
	}

	try {
		const payload = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
		req.user = payload.id;
		next();
	} catch (error) {
		if (error.name === 'TokenExpiredError') {
			return res
				.status(401)
				.json({ error: 'Session timed out,please login again' });
		} else if (error.name === 'JsonWebTokenError') {
			return res
				.status(401)
				.json({ error: 'Invalid token,please login again!' });
		} else {
			//catch other unprecedented errors
			console.error(error);
			return res.status(400).json({ error });
		}
	}
};
