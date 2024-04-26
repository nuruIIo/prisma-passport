import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
// import { CreateAuthDto } from './dto/create-auth.dto';
// import { UpdateAuthDto } from './dto/update-auth.dto';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { CreateAuthDto, UpdateAuthDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Request, Response } from 'express';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async getTokens(userId: number, email: string) {
    const jwtPayload = {
      sub: userId,
      email: email,
    };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await bcrypt.hash(refreshToken, 7);
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashedRefreshToken,
      },
    });
  }

  async signup(createAuthDto: CreateAuthDto, res: Response) {
    const candidate = await this.prismaService.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });

    if (candidate) {
      throw new BadRequestException('user already exists!');
    }

    const hashedPassword = await bcrypt.hash(createAuthDto.password, 7);

    const newUser = await this.prismaService.user.create({
      data: {
        email: createAuthDto.email,
        hashedPassword,
      },
    });

    const tokens = await this.getTokens(newUser.id, newUser.email);

    await this.updateRefreshToken(newUser.id, tokens.refresh_token);
    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });

    return tokens;
  }

  async login(createAuthDto: CreateAuthDto, res: Response) {
    const candidate = await this.prismaService.user.findUnique({
      where: {
        email: createAuthDto.email,
      },
    });

    if (!candidate) {
      throw new BadRequestException('user doesnt exists!');
    }

    const comparePassword = await bcrypt.compare(
      createAuthDto.password,
      candidate.hashedPassword,
    );

    if (!comparePassword) {
      throw new BadRequestException('incorrect password or email');
    }

    const tokens = await this.getTokens(candidate.id, candidate.email);

    await this.updateRefreshToken(candidate.id, tokens.refresh_token);

    res.cookie('refresh_token', tokens.refresh_token, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });

    return tokens;
  }

  async signout(res: Response) {
    res.clearCookie('refresh_token');
    return { message: 'Signed out successfully' };
  }

  // async refresh(req: Request, res: Response) {
  //   const refreshToken = req.cookies.refresh_token;

  //   if (!refreshToken) {
  //     throw new UnauthorizedException('Refresh token missing');
  //   }

  //   const decodedToken = jwt.verify(
  //     refreshToken,
  //     process.env.REFRESH_TOKEN_SECRET,
  //   );
  //   const userId = decodedToken.userId;
  //   const userEmail = decodedToken.email;

  //   const tokens = await this.getTokens(userId, userEmail);

  //   await this.updateRefreshToken(userId, tokens.refresh_token);

  //   res.cookie('refresh_token', tokens.refresh_token, {
  //     maxAge: Number(process.env.COOKIE_TIME),
  //     httpOnly: true,
  //   });

  //   return tokens.access_token;
  // }

  // async logout(userId: Number, res: Response) {
  //   const candidate = await this.prismaService.user.findUnique({
  //     where: {
  //       email: createAuthDto.email,
  //     },
  //   });

  //   if (!candidate) {
  //     throw new BadRequestException('user doesnt exists!');
  //   }

  //   const comparePassword = await bcrypt.compare(
  //     createAuthDto.password,
  //     candidate.hashedPassword,
  //   );

  //   if (!comparePassword) {
  //     throw new BadRequestException('incorrect password or email');
  //   }

  //   const tokens = await this.getTokens(candidate.id, candidate.email);

  //   await this.updateRefreshToken(candidate.id, tokens.refresh_token);

  //   res.cookie('refresh_token', tokens.refresh_token, {
  //     maxAge: Number(process.env.COOKIE_TIME),
  //     httpOnly: true,
  //   });

  //   return tokens;
  // }

  create(createAuthDto: CreateAuthDto) {
    return 'This action adds a new auth';
  }

  findAll() {
    return `This action returns all auth`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
