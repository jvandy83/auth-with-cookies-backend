import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	firstName: String,
	lastName: String,
	refreshToken: {
		type: Number,
		default: 0,
	},
});

export default mongoose.model('User', userSchema);
