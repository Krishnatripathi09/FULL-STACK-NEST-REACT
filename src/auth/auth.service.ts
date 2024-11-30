/* eslint-disable prettier/prettier */
import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt'
@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }

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
                password,
                UserName
            }
        })
        return { message: "Signup was successful" }
    }
    async signin(dto: AuthDto) {
        const { email, password } = dto;
        const foundUser = await this.prisma.user.findUnique({ where: { email } });
        return { message: "Signed-In Successfully" }

        if(!foundUser){
            throw new BadRequestException("Invalid Email or Password")

        }

        const isMatch = await this.comparePasswords({password,hash: foundUser.password})

        if(!isMatch){
            throw new BadRequestException("Please Enter Valid Credentials")
        }
    }
// Sign Jwt ans return User


    async signout() {
        return { message: "Signed-Out" }
    }

    async hashedPassword(password: string) {
        const saltOrRounds = 10;
        return await bcrypt.hash(password, saltOrRounds);

    }
    async comparePasswords(args: { password: string, hash: string }) {
        return await bcrypt.compare(args.password, args.hash)
    }
}
