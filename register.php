<?php
require __DIR__ . '/config_mysqli.php';
require __DIR__ . '/csrf.php';

/* =========================
   Register (minimal-change)
   ========================= */

$errors = [];
$success = "";
// คงตัวแปรเดิมไว้เพื่อแสดงค่าเดิมในฟอร์ม
$username = $email = $full_name = "";

// ฟังก์ชันกัน XSS เวลา echo กลับ
function e($str){ return htmlspecialchars($str ?? "", ENT_QUOTES, "UTF-8"); }

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // --- CSRF ให้ตรงระบบ (ใช้ name="csrf" + csrf_check()) ---
  if (empty($_POST['csrf']) || !csrf_check($_POST['csrf'])) {
    $errors[] = "CSRF token ไม่ถูกต้อง กรุณารีเฟรชหน้าแล้วลองอีกครั้ง";
  }

  // รับค่าจากฟอร์ม (คงชื่อฟิลด์เดิมไว้)
  $username  = trim($_POST['username'] ?? "");
  $password  = $_POST['password'] ?? "";
  $email     = trim($_POST['email'] ?? "");
  $full_name = trim($_POST['name'] ?? "");

  // ตรวจความถูกต้องเดิม ๆ (คง regex username ไว้ถึงแม้จะไม่บันทึกลง DB)
  if ($username === "" || !preg_match('/^[A-Za-z0-9_\.]{3,30}$/', $username)) {
    $errors[] = "กรุณากรอก username 3–30 ตัวอักษร (a-z, A-Z, 0-9, _, .)";
  }
  if (strlen($password) < 8) {
    $errors[] = "รหัสผ่านต้องยาวอย่างน้อย 8 ตัวอักษร";
  }
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = "อีเมลไม่ถูกต้อง";
  }
  if ($full_name === "" || mb_strlen($full_name) > 190) {
    $errors[] = "กรุณากรอกชื่อ–นามสกุล (ไม่เกิน 190 ตัวอักษร)";
  }

  // --- ตรวจซ้ำด้วยอีเมลอย่างเดียว (ตารางจริงไม่มี username) ---
  if (!$errors) {
    $sql = "SELECT 1 FROM users WHERE email = ? LIMIT 1";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
      $errors[] = "อีเมลนี้ถูกใช้แล้ว";
    }
    $stmt->close();
  }

  // --- INSERT ให้ตรงสคีมา: email, display_name, password_hash ---
  if (!$errors) {
    $password_hash = password_hash($password, PASSWORD_DEFAULT);
    $sql = "INSERT INTO users (email, display_name, password_hash) VALUES (?, ?, ?)";
    $stmt = $mysqli->prepare($sql);
    $stmt->bind_param("sss", $email, $full_name, $password_hash); // map $full_name -> display_name
    if ($stmt->execute()) {
      $success = "สมัครสมาชิกสำเร็จ! คุณสามารถล็อกอินได้แล้วค่ะ";
      // เคลียร์ฟอร์ม
      $username = $email = $full_name = "";
    } else {
      // duplicate email
      if ($mysqli->errno == 1062) {
        $errors[] = "อีเมลนี้ถูกใช้แล้ว";
      } else {
        $errors[] = "บันทึกข้อมูลไม่สำเร็จ: ".e($mysqli->error);
      }
    }
    $stmt->close();
  }
}
?>
<!doctype html>
<html lang="th">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>สมัครสมาชิก</title>
    <style>
        /* กำหนดตัวแปรสีเพื่อให้ปรับเปลี่ยนง่าย */
        :root {
            --primary-color: #4f46e5; /* Indigo */
            --primary-hover: #4338ca;
            --background-color: #f3f4f6; /* Light Gray Background */
            --card-bg: #ffffff;
            --border-color: #d1d5db; /* Gray Border */
            --success-bg: #ecfdf5;
            --success-text: #059669;
            --error-bg: #fef2f2;
            --error-text: #ef4444;
        }

        body {
            font-family: 'Inter', system-ui, sans-serif;
            background: var(--background-color);
            margin: 0;
            padding: 20px;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            box-sizing: border-box;
        }

        .container {
            width: 100%;
            max-width: 440px;
            background: var(--card-bg);
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }

        h1 {
            text-align: center;
            color: #1f2937;
            margin: 0 0 24px;
            font-size: 28px;
            font-weight: 700;
        }

        /* ปรับปรุง Alert Box */
        .alert {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            line-height: 1.5;
            display: flex; /* เพื่อจัดเรียงข้อความ Error */
            flex-direction: column;
        }

        .alert.error {
            background: var(--error-bg);
            color: var(--error-text);
            border: 1px solid #fca5a5;
        }

        .alert.success {
            background: var(--success-bg);
            color: var(--success-text);
            border: 1px solid #6ee7b7;
        }
        
        /* ปรับปรุงฟอร์มและปุ่ม */
        label {
            display: block;
            font-size: 14px;
            font-weight: 600;
            color: #374151;
            margin: 16px 0 8px;
        }

        /* ใช้ Attribute Selector เพื่อให้มีผลกับ input ทุกประเภท */
        input[type="text"], 
        input[type="password"], 
        input[type="email"] {
            width: 100%;
            padding: 12px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
            box-shadow: inset 0 1px 2px rgba(0, 0, 0, 0.05);
            transition: border-color 0.15s ease-in-out, box-shadow 0.15s ease-in-out;
            box-sizing: border-box; 
        }

        input:focus {
            border-color: var(--primary-color);
            outline: 0;
            box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.25);
        }

        button {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            margin-top: 24px;
            background: var(--primary-color);
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s ease;
        }

        button:hover {
            background: var(--primary-hover);
        }

        .hint {
            font-size: 12px;
            color: #6b7280;
            margin-top: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>สมัครสมาชิก</h1>

        <?php if (!empty($errors)): ?>
            <div class="alert error">
                <?php foreach ($errors as $m) echo "<div>".e($m)."</div>"; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($success)): ?>
            <div class="alert success"><?= e($success) ?></div>
        <?php endif; ?>

        <form method="post" action="">
            <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">

            <label for="username">Username</label>
            <input type="text" id="username" name="username" value="<?= e($username) ?>" required>
            <div class="hint">อนุญาต a-z, A-Z, 0-9, _ และ . (3–30 ตัว)</div>

            <label for="password">Password</label>
            <input type="password" id="password" name="password" required>
            <div class="hint">อย่างน้อย 8 ตัวอักษร</div>

            <label for="email">Email</label>
            <input type="email" id="email" name="email" value="<?= e($email) ?>" required>

            <label for="name">ชื่อ–นามสกุล</label>
            <input type="text" id="name" name="name" value="<?= e($full_name) ?>" required>

            <button type="submit">สมัครสมาชิก</button>
        </form>
    </div>
</body>
</html>