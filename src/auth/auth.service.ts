/* eslint-disable prettier/prettier */
import { BadRequestException, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto, SignInDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from '../utils/constants'
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService) { }

    async signup(dto: AuthDto) {
        const { UserName, email, password } = dto;
        const foundUser = await this.prisma.user.findUnique({ where: { email } });
        if (foundUser) {
            throw new BadRequestException("Email is Already registered ! Please Proceed to Login")
        }
        const hashedPassword = await this.hashedPassword(password);

        await this.prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                UserName
            }
        })
        return { message: "Signup was successful" }
    }
    async signin(dto: SignInDto, req: Request, res: Response,) {
        const { email, password } = dto;
        const foundUser = await this.prisma.user.findUnique({ where: { email } });

        if (!foundUser) {
            throw new BadRequestException("Invalid Email or Password");
        }

        const isMatch = await this.comparePasswords({ password, hash: foundUser.password });

        if (!isMatch) {
            throw new BadRequestException("Please Enter Valid Credentials");
        }

        // Sign JWT and return User
        const token = await this.signToken({ id: foundUser.id, email: foundUser.email });

        if (!token) {
            throw new ForbiddenException("ForBidden")
        }
        res.cookie('token', token)
        return res.send({ message: "Logged in SuccessFully" });  // Ensure this line is executed.
    }



    async signout(req: Request, res: Response,) {
        res.clearCookie('token')
        return res.send({ message: "Signed-Out Successfuly" })
    }

    async hashedPassword(password: string) {
        const saltOrRounds = 10;
        return await bcrypt.hash(password, saltOrRounds);

    }
    async comparePasswords(args: { password: string, hash: string }) {
        return await bcrypt.compare(args.password, args.hash)
    }

    async signToken(args: { id: string, email: string }) {
        const payload = args

        return this.jwt.signAsync(payload, { secret: jwtSecret })
    }

}
