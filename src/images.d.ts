declare module '*.png' {
  const src: import('react-native').ImageSourcePropType;
  export default src;
}
declare module '*.wav' {
  const src: number;
  export default src;
}
