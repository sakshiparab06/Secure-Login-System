router.get('/login', (req, res) => {
  res.render('login');
});

router.post('/login', async (req, res) => {

  const { email, password } = req.body;

  try {

    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).send('Invalid credentials');
    }

    const user = result.rows[0];

    const valid =
      await bcrypt.compare(
        password,
        user.password_hash
      );

    if (!valid) {
      return res.status(401).send('Invalid credentials');
    }

    req.session.userId = user.id;

    res.redirect('/dashboard');

  } catch (err) {
    res.status(500).send('Login failed');
  }
});