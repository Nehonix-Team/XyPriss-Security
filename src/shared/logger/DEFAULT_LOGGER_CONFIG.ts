export type LoggerConfig = NonNullable<any["logging"]>;

export const DEFAULT_LOGGER_CONFIG: LoggerConfig = {
  enabled: true,
  level: "info",
};
