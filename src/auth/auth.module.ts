/* eslint-disable prettier/prettier */
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt'
import { jwtSecret } from '../utils/constants';
@Module({
  imports: [JwtModule.register({
    secret: jwtSecret,
    signOptions: { expiresIn: '1h' }, // Set token expiration time
  }),],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule { }
