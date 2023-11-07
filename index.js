const express = require("express");
const port = 3000;
const app = express();
const bodyParser = require("body-parser");
const Auth = require("./Routes/Auth");
const cors = require("cors");
app.use(bodyParser.json());
app.use(cors());

app.get("/", (req, res) => {
  res.json("API working");
});

app.use("/auth", Auth);

app.listen(port, () => {
  console.log(`server is running on port ${port}`);
});
