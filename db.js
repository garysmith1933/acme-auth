const Sequelize = require('sequelize');
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const { STRING } = Sequelize;
const config = {
  logging: false
};

if(process.env.LOGGING){
  delete config.logging;
}
const conn = new Sequelize(process.env.DATABASE_URL || 'postgres://localhost/acme_db', config);

const User = conn.define('user', {
  username: STRING,
  password: STRING
});

//creates a hashed version of the password.
User.addHook('beforeSave', async(user) => {
  if(user.changed('password')) {
    const hashed = await bcrypt.hash(user.password, 3);
    user.password = hashed;
    console.log(hashed);
  }
});

User.byToken = async(token)=> {
  try {
    const payload = await jwt.verify(token, process.env.JWT)
    //we can exclude the password so that its not shown in the console response.
    const user = await User.findByPk(payload.id, {
      attributes: {
        exclude: ['password']
      }
    });
    if(user){
      return user;
    }
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
  catch(ex){
    const error = Error('bad credentials');
    error.status = 401;
    throw error;
  }
};

User.authenticate = async({ username, password })=> {
  const user = await User.findOne({
    where: {
      username
    }
  });
  //the order matters, hashed password, the unhashed pass
  if(user && await bcrypt.compare(password, user.password)){
    return jwt.sign({id: user.id}, process.env.JWT); 
  }
  const error = Error('bad credentials!!!!!!');
  error.status = 401;
  throw error;
};

const syncAndSeed = async()=> {
  await conn.sync({ force: true });
  const credentials = [
    { username: 'lucy', password: 'lucy_pw'},
    { username: 'moe', password: 'moe_pw'},
    { username: 'larry', password: 'larry_pw'}
  ];
  const [lucy, moe, larry] = await Promise.all(
    credentials.map( credential => User.create(credential))
  );
  return {
    users: {
      lucy,
      moe,
      larry
    }
  };
};

module.exports = {
  syncAndSeed,
  models: {
    User
  }
};
