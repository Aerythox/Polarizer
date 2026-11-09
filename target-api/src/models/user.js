import mongoose from 'mongoose';

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
});

// Never send the password hash in a response, in either mode.
userSchema.set('toJSON', {
  transform: (_doc, user) => {
    delete user.passwordHash;
    delete user.__v;
    return user;
  },
});

export const User = mongoose.model('User', userSchema);
