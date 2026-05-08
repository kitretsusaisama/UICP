import { User } from '../entities/user.entity';
import { Consistency } from '../../infrastructure/db/mysql/consistency.enum';

export interface IUserRepository {
  save(user: User): Promise<void>;
  findById(id: string, consistency?: Consistency): Promise<User | null>;
  findByEmail(email: string, consistency?: Consistency): Promise<User | null>;
  findByPhone(phone: string, consistency?: Consistency): Promise<User | null>;
}

export const USER_REPOSITORY = 'USER_REPOSITORY';
