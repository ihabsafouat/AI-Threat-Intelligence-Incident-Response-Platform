import { create } from 'zustand';

interface AuthState {
  isAuthenticated: boolean;
  user: any | null;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  logout: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  isAuthenticated: true, // Set to true for demo purposes
  user: {
    id: 1,
    name: 'Admin User',
    email: 'admin@example.com',
    role: 'admin'
  },
  login: async (credentials) => {
    // Simulate login
    set({
      isAuthenticated: true,
      user: {
        id: 1,
        name: 'Admin User',
        email: credentials.email,
        role: 'admin'
      }
    });
  },
  logout: () => {
    set({
      isAuthenticated: false,
      user: null
    });
  }
})); 