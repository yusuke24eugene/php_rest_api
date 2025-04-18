<?php
header("Content-Type: application/json");
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");

require_once 'config.php';

// Get HTTP method
$method = $_SERVER['REQUEST_METHOD'];

// Get request parameters
$request = explode('/', trim($_SERVER['PATH_INFO'], '/'));
$input = json_decode(file_get_contents('php://input'), true);

// Database connection
try {
    $pdo = new PDO("mysql:host=" . DB_HOST . ";dbname=" . DB_NAME, DB_USER, DB_PASS);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Database connection failed']);
    exit;
}

// Route the request
switch ($method) {
    case 'GET':
        handleGetRequest($pdo, $request);
        break;
    case 'POST':
        handlePostRequest($pdo, $input);
        break;
    case 'PUT':
        handlePutRequest($pdo, $request, $input);
        break;
    case 'DELETE':
        handleDeleteRequest($pdo, $request);
        break;
    default:
        http_response_code(405);
        echo json_encode(['error' => 'Method not allowed']);
        break;
}

function handleGetRequest($pdo, $request)
{
    if (empty($request[0])) {
        // Get all items
        $stmt = $pdo->query("SELECT * FROM items");
        $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
        echo json_encode($items);
    } else {
        // Get single item
        $id = $request[0];
        $stmt = $pdo->prepare("SELECT * FROM items WHERE id = ?");
        $stmt->execute([$id]);
        $item = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($item) {
            echo json_encode($item);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
        }
    }
}

function handlePostRequest($pdo, $input)
{
    if (!empty($input['name']) && !empty($input['description'])) {
        $stmt = $pdo->prepare("INSERT INTO items (name, description) VALUES (?, ?)");
        $stmt->execute([$input['name'], $input['description']]);
        $id = $pdo->lastInsertId();

        http_response_code(201);
        echo json_encode([
            'id' => $id,
            'name' => $input['name'],
            'description' => $input['description']
        ]);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
    }
}

function handlePutRequest($pdo, $request, $input)
{
    if (!empty($request[0]) && !empty($input['name']) && !empty($input['description'])) {
        $id = $request[0];

        $stmt = $pdo->prepare("UPDATE items SET name = ?, description = ? WHERE id = ?");
        $stmt->execute([$input['name'], $input['description'], $id]);

        if ($stmt->rowCount() > 0) {
            echo json_encode([
                'id' => $id,
                'name' => $input['name'],
                'description' => $input['description']
            ]);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Missing required fields']);
    }
}

function handleDeleteRequest($pdo, $request)
{
    if (!empty($request[0])) {
        $id = $request[0];
        $stmt = $pdo->prepare("DELETE FROM items WHERE id = ?");
        $stmt->execute([$id]);

        if ($stmt->rowCount() > 0) {
            echo json_encode(['message' => 'Item deleted successfully']);
        } else {
            http_response_code(404);
            echo json_encode(['error' => 'Item not found']);
        }
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Missing item ID']);
    }
}
