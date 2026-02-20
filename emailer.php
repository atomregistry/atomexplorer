<?php
/**
 * Atom Registry — Contact Form Mailer (SMTP)
 * ────────────────────────────────────────────────────────────────────────────
 * Uses direct SMTP over SSL — no mail(), no PHPMailer, no dependencies.
 * Place in same directory as contact.html.
 */

// ── CONFIG ────────────────────────────────────────────────────────────────────

define('SMTP_HOST',       'mail.atomregistry.com');
define('SMTP_PORT',       465);
define('SMTP_USER',       'hello@atomregistry.com');
define('SMTP_PASS',       'Bigmoney247$$'); // ← only change needed
define('SMTP_FROM_NAME',  'Atom Registry Contact');
define('SMTP_FROM_EMAIL', 'hello@atomregistry.com');

define('RECIPIENT_EMAIL', 'hello@atomregistry.com');
define('RECIPIENT_NAME',  'Atom Registry');
define('SITE_NAME',       'Atom Registry');
define('SITE_URL',        'https://explorer.atomregistry.com');
define('RATE_LIMIT_MAX',   5);
define('RATE_LIMIT_SECS',  300);

// ── SMTP FUNCTION ─────────────────────────────────────────────────────────────

function smtp_send(string $to_name, string $to_email, string $from_name,
                   string $from_email, string $reply_to,
                   string $subject, string $body_html): bool|string
{
    $sock = @fsockopen('ssl://' . SMTP_HOST, SMTP_PORT, $errno, $errstr, 15);
    if (!$sock) return "Connection failed: $errstr ($errno)";

    $read = function() use ($sock): string {
        $r = '';
        while ($line = fgets($sock, 512)) {
            $r .= $line;
            if (substr($line, 3, 1) === ' ') break;
        }
        return $r;
    };
    $cmd = function(string $c) use ($sock, $read): string {
        fwrite($sock, $c . "\r\n");
        return $read();
    };

    $r = $read();
    if (substr($r, 0, 3) !== '220') { fclose($sock); return "Bad greeting: $r"; }

    $r = $cmd('EHLO ' . parse_url(SITE_URL, PHP_URL_HOST));
    if (substr($r, 0, 3) !== '250') { fclose($sock); return "EHLO failed: $r"; }

    $r = $cmd('AUTH LOGIN');
    if (substr($r, 0, 3) !== '334') { fclose($sock); return "AUTH failed: $r"; }

    $r = $cmd(base64_encode(SMTP_USER));
    if (substr($r, 0, 3) !== '334') { fclose($sock); return "Username rejected: $r"; }

    $r = $cmd(base64_encode(SMTP_PASS));
    if (substr($r, 0, 3) !== '235') { fclose($sock); return "Password rejected: $r"; }

    $r = $cmd('MAIL FROM:<' . $from_email . '>');
    if (substr($r, 0, 3) !== '250') { fclose($sock); return "MAIL FROM failed: $r"; }

    $r = $cmd('RCPT TO:<' . $to_email . '>');
    if (substr($r, 0, 3) !== '250') { fclose($sock); return "RCPT TO failed: $r"; }

    $r = $cmd('DATA');
    if (substr($r, 0, 3) !== '354') { fclose($sock); return "DATA failed: $r"; }

    $boundary = 'AR_' . md5(uniqid('', true));
    $body_plain = wordwrap(strip_tags(preg_replace('/<br\s*\/?>/', "\n", $body_html)), 76, "\r\n");

    $msg = implode("\r\n", [
        'From: ' . $from_name . ' <' . $from_email . '>',
        'To: ' . $to_name . ' <' . $to_email . '>',
        'Reply-To: ' . $reply_to,
        'Subject: ' . $subject,
        'MIME-Version: 1.0',
        'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        'X-Mailer: AtomRegistry-Mailer/2.0',
        'Date: ' . date('r'),
        '',
        '--' . $boundary,
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        quoted_printable_encode($body_plain),
        '',
        '--' . $boundary,
        'Content-Type: text/html; charset=UTF-8',
        'Content-Transfer-Encoding: quoted-printable',
        '',
        quoted_printable_encode($body_html),
        '',
        '--' . $boundary . '--',
    ]);

    // Dot-stuff
    $msg = preg_replace('/^\./', '..', $msg);

    fwrite($sock, $msg . "\r\n.\r\n");
    $r = $read();
    if (substr($r, 0, 3) !== '250') { fclose($sock); return "Message rejected: $r"; }

    $cmd('QUIT');
    fclose($sock);
    return true;
}

// ── BOOTSTRAP ────────────────────────────────────────────────────────────────

header('Access-Control-Allow-Origin: ' . SITE_URL);
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit(json_encode(['ok' => false, 'error' => 'Method not allowed.']));
}

// ── CSRF ──────────────────────────────────────────────────────────────────────

$origin  = $_SERVER['HTTP_ORIGIN']  ?? '';
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$ok = false;
foreach (['https://explorer.atomregistry.com', 'https://atomregistry.com', 'http://localhost'] as $a) {
    if (str_starts_with($origin, $a) || str_starts_with($referer, $a)) { $ok = true; break; }
}
if (!$ok) {
    http_response_code(403);
    exit(json_encode(['ok' => false, 'error' => 'Forbidden.']));
}

// ── RATE LIMIT ────────────────────────────────────────────────────────────────

session_start();
$ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
$key = 'rl_' . md5($ip);
$now = time();
if (!isset($_SESSION[$key])) $_SESSION[$key] = ['count' => 0, 'start' => $now];
$rl = &$_SESSION[$key];
if ($now - $rl['start'] > RATE_LIMIT_SECS) $rl = ['count' => 0, 'start' => $now];
if ($rl['count'] >= RATE_LIMIT_MAX) {
    http_response_code(429);
    exit(json_encode(['ok' => false, 'error' => 'Too many submissions. Please wait a few minutes.']));
}
$rl['count']++;

// ── INPUT + SANITIZE ─────────────────────────────────────────────────────────

$data = json_decode(file_get_contents('php://input'), true) ?: $_POST;

function clean(string $v): string {
    return htmlspecialchars(trim(preg_replace('/[\r\n\t]/', ' ', $v)), ENT_QUOTES, 'UTF-8');
}

$fname   = clean($data['fname']   ?? '');
$lname   = clean($data['lname']   ?? '');
$email   = trim($data['email']    ?? '');
$subject = clean($data['subject'] ?? '');
$message = trim($data['message']  ?? '');
$chainId = clean($data['chainId'] ?? '');
$honey   = trim($data['website']  ?? '');

if ($honey !== '') exit(json_encode(['ok' => true])); // honeypot

// ── VALIDATION ────────────────────────────────────────────────────────────────

$errors = [];
if (strlen($fname) < 1)  $errors[] = 'First name is required.';
if (strlen($fname) > 80) $errors[] = 'First name is too long.';
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = 'A valid email address is required.';
if (strlen($email) > 254) $errors[] = 'Email address is too long.';
if (!in_array($subject, ['bug','chain','feature','advertising','press','partnership','other'], true))
    $errors[] = 'Please select a valid topic.';
if (strlen(trim($message)) < 10) $errors[] = 'Message must be at least 10 characters.';
if (strlen($message) > 8000)     $errors[] = 'Message is too long (max 8000 characters).';

if (!empty($errors)) {
    http_response_code(422);
    exit(json_encode(['ok' => false, 'error' => implode(' ', $errors)]));
}

// ── BUILD EMAILS ──────────────────────────────────────────────────────────────

$labels = [
    'bug' => 'Bug Report / Technical Issue', 'chain' => 'Chain Support Request',
    'feature' => 'Feature Request', 'advertising' => 'Advertising / Sponsorship',
    'press' => 'Press / Media Inquiry', 'partnership' => 'Partnership Opportunity',
    'other' => 'Other',
];
$label      = $labels[$subject] ?? $subject;
$full_name  = trim("$fname $lname");
$date       = date('Y-m-d H:i:s T');
$msg_html   = nl2br(htmlspecialchars($message, ENT_QUOTES, 'UTF-8'));
$safe_name  = preg_replace('/[^a-zA-Z0-9 \.\-]/', '', $full_name);
$safe_email = filter_var($email, FILTER_SANITIZE_EMAIL);
$chain_row  = $chainId !== ''
    ? "<tr><td style='padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace;width:100px'>Chain ID</td><td style='padding:6px 0;color:#e8f4fc;font-size:12px;font-family:monospace'>$chainId</td></tr>"
    : '';

$notify_html = <<<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#020810;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#020810;padding:32px 0"><tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#040d1a;border:1px solid rgba(0,229,255,0.15);border-radius:8px;overflow:hidden;max-width:600px">
  <tr><td style="background:linear-gradient(135deg,#040d1a,#0a1d33);padding:24px 32px;border-bottom:1px solid rgba(0,229,255,0.1)">
    <span style="font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#00e5ff;font-weight:900">ATOM REGISTRY</span>
    <span style="font-family:monospace;font-size:11px;color:#2a4a6a;letter-spacing:2px;display:block;margin-top:2px">CONTACT FORM SUBMISSION</span>
  </td></tr>
  <tr><td style="padding:24px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#071525;border:1px solid rgba(0,229,255,0.06);border-radius:6px;padding:16px">
      <tr><td style="padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace;width:100px">Name</td><td style="padding:6px 0;color:#e8f4fc;font-size:12px;font-family:monospace">$full_name</td></tr>
      <tr><td style="padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace">Email</td><td style="padding:6px 0;font-size:12px;font-family:monospace"><a href="mailto:$email" style="color:#00e5ff;text-decoration:none">$email</a></td></tr>
      <tr><td style="padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace">Topic</td><td style="padding:6px 0;color:#e8f4fc;font-size:12px;font-family:monospace">$label</td></tr>
      $chain_row
      <tr><td style="padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace">Date</td><td style="padding:6px 0;color:#2a4a6a;font-size:11px;font-family:monospace">$date</td></tr>
      <tr><td style="padding:6px 0;color:#8ab4c8;font-size:12px;font-family:monospace">IP</td><td style="padding:6px 0;color:#2a4a6a;font-size:11px;font-family:monospace">$ip</td></tr>
    </table>
  </td></tr>
  <tr><td style="padding:20px 32px 0">
    <div style="font-family:monospace;font-size:10px;letter-spacing:2px;color:#2a4a6a;margin-bottom:8px">MESSAGE</div>
    <div style="background:#071525;border:1px solid rgba(0,229,255,0.06);border-left:3px solid #00e5ff;border-radius:6px;padding:16px 18px;font-family:monospace;font-size:13px;color:#c8dde8;line-height:1.8">$msg_html</div>
  </td></tr>
  <tr><td style="padding:20px 32px 24px">
    <span style="font-family:monospace;font-size:10px;color:#2a4a6a">via explorer.atomregistry.com/contact.html</span>
  </td></tr>
</table></td></tr></table></body></html>
HTML;

$reply_html = <<<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#020810;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#020810;padding:32px 0"><tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#040d1a;border:1px solid rgba(0,229,255,0.15);border-radius:8px;overflow:hidden;max-width:600px">
  <tr><td style="background:linear-gradient(135deg,#040d1a,#0a1d33);padding:24px 32px;border-bottom:1px solid rgba(0,229,255,0.1)">
    <span style="font-family:Arial,sans-serif;font-size:22px;letter-spacing:4px;color:#00e5ff;font-weight:900">ATOM REGISTRY</span>
    <span style="font-family:monospace;font-size:11px;color:#2a4a6a;letter-spacing:2px;display:block;margin-top:2px">MESSAGE RECEIVED</span>
  </td></tr>
  <tr><td style="padding:28px 32px">
    <p style="font-size:14px;color:#c8dde8;line-height:1.8;margin:0 0 16px">Hi $fname,</p>
    <p style="font-size:14px;color:#c8dde8;line-height:1.8;margin:0 0 16px">Thanks for reaching out. We've received your message and will get back to you within 24–48 hours.</p>
    <p style="font-size:14px;color:#c8dde8;line-height:1.8;margin:0 0 24px">In the meantime feel free to explore <a href="https://explorer.atomregistry.com" style="color:#00e5ff;text-decoration:none">Atom Registry</a> across any of the 28+ supported Cosmos chains.</p>
    <div style="background:#071525;border:1px solid rgba(0,229,255,0.06);border-left:3px solid #00e5ff;border-radius:6px;padding:14px 18px;font-family:monospace;font-size:11px;color:#2a4a6a;line-height:1.7">
      Topic: $label<br>Submitted: $date
    </div>
  </td></tr>
  <tr><td style="padding:0 32px 24px;border-top:1px solid rgba(0,229,255,0.06)">
    <p style="font-family:monospace;font-size:10px;color:#2a4a6a;margin:20px 0 0">Automated confirmation — to add anything email <a href="mailto:hello@atomregistry.com" style="color:#2a4a6a">hello@atomregistry.com</a> directly.</p>
  </td></tr>
</table></td></tr></table></body></html>
HTML;

// ── SEND ──────────────────────────────────────────────────────────────────────

$result = smtp_send(
    RECIPIENT_NAME, RECIPIENT_EMAIL,
    SMTP_FROM_NAME, SMTP_FROM_EMAIL,
    "$safe_name <$safe_email>",
    '[' . SITE_NAME . '] ' . $label . ' from ' . $safe_name,
    $notify_html
);

if ($result !== true) {
    http_response_code(500);
    exit(json_encode([
        'ok'    => false,
        'error' => 'Mail server error. Please email us directly at ' . RECIPIENT_EMAIL,
        'debug' => $result   // ← remove this line once confirmed working
    ]));
}

// Best-effort auto-reply
smtp_send(
    $safe_name, $safe_email,
    RECIPIENT_NAME, RECIPIENT_EMAIL,
    RECIPIENT_NAME . ' <' . RECIPIENT_EMAIL . '>',
    'We got your message — ' . SITE_NAME,
    $reply_html
);

http_response_code(200);
exit(json_encode(['ok' => true]));