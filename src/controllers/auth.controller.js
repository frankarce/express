import User from '../models/user.models.js';
import bcrypt from 'bcryptjs';
export const register = async (req, res) => {
    const { name, email, password } = req.body;
    //User.create({ name, email, password });
    try {
        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password : passwordHash });
        await newUser.save();
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: 'Error al registrar el usuario' });
    }
    res.send('registrado'); 
};










export const login = (req, res) => {};