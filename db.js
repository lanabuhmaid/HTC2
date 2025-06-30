// db.js
import pg from "pg";
import pkg from "pg";
const { Pool } = pkg;

const db = new pg.Client(
  "postgresql://postgres.dctbfwejkssojlvkcpol:4412106@aws-0-eu-central-1.pooler.supabase.com:6543/postgres"
);

await db
  .connect()
  .then(() => {
    console.log(
      "✅ the Connection has been established successfully to SUPBASE"
    );
  })
  .catch((err) => {
    console.log(err);
  }); // You can also handle errors here if needed
 
export default db;
