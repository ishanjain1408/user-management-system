import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/db';
import { sendVerificationEmail } from '../utils/email';

const register = async (req: Request, res: Response): Promise<void> => {
  const { firstName, lastName, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET!, { expiresIn: '1h' });

  try {
    await pool.query(
      'INSERT INTO users (first_name, last_name, email, password, role, verification_token) VALUES (?, ?, ?, ?, ?, ?)',
      [firstName, lastName, email, hashedPassword, role, verificationToken]
    );

    await sendVerificationEmail(email, verificationToken);
    res.status(201).json({ message: 'User registered. Please check your email for verification.' });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed' });
  }
};

const verifyEmail = async (req: Request, res: Response): Promise<void> => {
  const { token } = req.query;

  try {
    const decoded: any = jwt.verify(token as string, process.env.JWT_SECRET!);
    await pool.query('UPDATE users SET is_verified = TRUE WHERE email = ?', [decoded.email]);
    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    res.status(400).json({ error: 'Invalid or expired token' });
  }
};

const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;

  try {
    const [rows]: any = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(400).json({ error: 'Invalid credentials' });
      return;
    }

    if (!user.is_verified) {
      res.status(400).json({ error: 'Please verify your email first' });
      return;
    }

    if (user.role === 'customer') {
      res.status(403).json({ error: 'You are not allowed to login from here' });
      return;
    }

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET!, { expiresIn: '1h' });
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
};

export { register, verifyEmail, login };