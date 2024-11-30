/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unused-vars */

import { IsEmail, IsNotEmpty, IsString, Length } from 'class-validator';

export class AuthDto {

    @IsNotEmpty()
    @IsString()
    public UserName: string;

    @IsEmail()
    @IsNotEmpty()
    @IsString()
    public email: string;



    @IsNotEmpty()
    @IsString()
    @Length(6, 20, { message: 'Password has to be at between 6 and 20 Characters' })
    public password: string;

}

export class SignInDto {
    @IsEmail()
    @IsNotEmpty()
    email: string;

    @IsNotEmpty()
    @Length(6, 20, { message: 'Password has to be at between 6 and 20 Characters' })
    password: string;
}