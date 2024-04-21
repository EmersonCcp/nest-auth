import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import { RegisterDto } from './dto/register.dto';
import * as bcryptjs from 'bcryptjs';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private jwtService: JwtService,
  ) {}

  async register({ username, email, password }: RegisterDto) {
    let user = await this.userService.findOneByEmail(email);

    if (user) {
      throw new BadRequestException('El Email ya esta registrado!');
    }

    user = await this.userService.findOneByUsername(username);

    if (user) {
      throw new BadRequestException('El Username ya esta registrado!');
    }

    return await this.userService.create({
      username,
      email,
      password: await bcryptjs.hash(password, 10),
    });
  }

  async login({ email, password }: LoginDto) {
    const user = await this.userService.findOneByEmail(email);

    if (!user) {
      throw new UnauthorizedException('Email is wrong');
    }

    const isPasswordValid = await bcryptjs.compare(password, user.password);

    if (!isPasswordValid) {
      throw new UnauthorizedException('Password is wrong');
    }

    const payload = { email: user.email };

    const token = await this.jwtService.signAsync(payload);

    return {
      token,
      email,
    };
  }
}
