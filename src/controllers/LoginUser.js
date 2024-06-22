import User from "../models/User.js";
import bcrypt from "bcryptjs";


async function loginUser(req, res) {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    const jwt = require ('jsonwebtoken');
    const SECRET = 'itapecurutools'; 

    if (!user) {
      return res.status(404).json({ message: 'Usuário não encontrado.' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Senha incorreta.' });
    }

      const token = jwt.sign ({userId: 1}, SECRET, {expireIn: 600 });
      return res.json({auth: true, token});
    res.status(200).json({ message: 'Login bem-sucedido!' });
  } catch (error) {
    console.error('Erro ao fazer login:', error);
    res.status(500).json({ message: 'Erro interno do servidor.' });
  }
}

function verifyJWT(req, res, next){
  const token = req.headers['x-access-token'];
  jwt.verify(token, SECRET, (err, decoded) => {
  if(err) return res.status(401).end();

  req.userId = decoded.userId;
  next();
  })
}

export { loginUser, verifyJWT};
