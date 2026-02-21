const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.send('Hello, pipeline.... pqrs - new deployment with PR !!!');
});

app.listen(PORT, () => {
    console.log(`Server.. is running on port ${PORT}`);
});
