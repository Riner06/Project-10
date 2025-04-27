const mysql = require("mysql2/promise")

async function getDBConnnection() {
    // Här skapas ett databaskopplings-objekt med inställningar för att ansluta till servern och databasen.
    return await mysql.createConnection({
      host: "localhost",
      user: "root",
      password: "my-secret-pw",
      database: "rest-api",
    })
  }
console.log('Connection successful');
  module.exports = {
    getDBConnnection
  }