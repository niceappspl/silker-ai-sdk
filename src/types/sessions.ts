/**
 * Sesja użytkownika używana do analizy zachowania.
 */
export interface UserSession {
  /** Adres IP użytkownika */
  ip: string;
  /** User-Agent użytkownika */
  userAgent: string;
  /** Czas rozpoczęcia sesji */
  startTime: number;
  /** Czas ostatniej aktywności */
  lastActivity: number;
  /** Liczba żądań w sesji */
  requestCount: number;
  /** Zbiór endpointów odwiedzonych w sesji */
  endpoints: Set<string>;
  /** Zbiór metod HTTP użytych w sesji */
  methods: Set<string>;
  /** Tablica odstępów czasowych między żądaniami */
  timeBetweenRequests: number[];
  /** Średni odstęp czasowy między żądaniami */
  averageRequestInterval: number;
  /** Czy sesja jest zidentyfikowana jako bot */
  isBot: boolean;
  /** Wynik anomalii dla sesji */
  anomalyScore: number;
}

