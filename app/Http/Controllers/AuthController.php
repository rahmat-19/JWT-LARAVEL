<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api')->except(['login', 'register']);
    }


    public function register(Request $request)
    {
        $validateData = $request->validate([
            'name' => 'required',
            'email' => 'required|email:rfc,dns|unique:users',
            'password' => 'required|min:6|confirmed'
        ]);

        $validateData['password'] = bcrypt($validateData['password']);

        $user = User::create($validateData);
        return response()->json([
            'massage' => 'successfuly registered',
            'status' => 201,
        ]);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|email:rfc,dns',
            'password' => 'required|min:6'
        ]);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json([
                'massage' => 'Wrong Email Or Password, Or Not Registered',
                'error' => 'Unauthorized',
                "status" => 401,
            ]);
        }

        return $this->respondWithToken($token);
    }






    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }

    public function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60

        ]);
    }
    public function logout()
    {
        auth()->logout();
        return response()->json(['message' => 'Successfully logged out']);
    }

    public function user()
    {
        return auth()->user();
    }
}
