const authMiddleware =
require('../middleware/authMiddleware');

router.get(
  '/dashboard',
  authMiddleware,
  (req, res) => {
    res.render('dashboard');
});