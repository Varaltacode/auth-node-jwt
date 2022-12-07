const mongoose = require('mongoose')

class db{
    static connect(){
        mongoose.connect('mongodb://localhost:27017/node_jwt')
        console.log('DB connected')
    }
}

module.exports = db