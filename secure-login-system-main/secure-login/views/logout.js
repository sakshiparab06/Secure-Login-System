router.get('/logout', (req, res) => {

  req.session.destroy(err => {

    if (err) {
      return res.status(500)
      .send('Logout failed');
    }

    res.clearCookie('connect.sid');

    res.redirect('/login');
  });

});