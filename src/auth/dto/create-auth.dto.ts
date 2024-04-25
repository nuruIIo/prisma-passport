import { IsEmail, IsOptional, IsString } from 'class-validator';

export class CreateAuthDto {
  @IsOptional()
  @IsString()
  readonly name?: string;

  @IsEmail()
  readonly email: string;

  @IsString()
  readonly password: string;
}
