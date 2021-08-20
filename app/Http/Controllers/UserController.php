<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class UserController extends Controller
{
    public function register(Request $request)
    {
        $fields = $request->validate([
            'name'=>'required|string',
            'phone_number'=>'required|digits:10',
            'email'=>'required|string|unique:users,email',
            'password'=>'required|string|confirmed'
        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'phone_number' => $fields['phone_number'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('myapptoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    public function login(Request $request)
    {
        $fields = $request->validate([
            //'email'=>'required|string',
            'phone_number'=>'required|digits:10',
            'password'=>'required|string'
        ]);

        $user = User::where('phone_number', $fields['phone_number'])->first();
        if(!$user || !Hash::check($fields['password'], $user->password))
        {
            return response([
                'message'=> 'Bad Credentials'
            ], 401);
        }
        
        $token = $user->createToken('myapptoken')->plainTextToken;
        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }    

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();
        return [
            'message'=> 'Logged Out'
        ];
    }
}
