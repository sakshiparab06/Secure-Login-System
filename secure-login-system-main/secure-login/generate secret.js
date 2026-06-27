const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

router.get('/2fa/setup', async (req, res) => {

  const secret = speakeasy.generateSecret({
    name: 'SecureLoginApp'
  });

  await pool.query(
    'UPDATE users SET twofa_secret=$1 WHERE id=$2',
    [secret.base32, req.session.userId]
  );

  const qr =
    await QRCode.toDataURL(secret.otpauth_url);

  res.send(`<img src="${qr}" />`);
});