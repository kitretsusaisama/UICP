/**
 * App Router Root — Main entry page redirects to dashboard or login
 */

import { redirect } from 'next/navigation';
import { authService } from '@/services/auth.service';

export default function HomePage() {
  if (authService.isAuthenticated()) {
    redirect('/dashboard/overview');
  } else {
    redirect('/login');
  }
}