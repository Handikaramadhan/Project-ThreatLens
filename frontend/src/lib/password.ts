export const PASSWORD_MIN_LENGTH = 15;

export type PasswordRequirement = {
  label: string;
  met: boolean;
};

export function analyzePassword(password: string) {
  const requirements: PasswordRequirement[] = [
    { label: `Minimal ${PASSWORD_MIN_LENGTH} karakter`, met: password.length >= PASSWORD_MIN_LENGTH },
    { label: "Minimal 1 huruf besar", met: /\p{Lu}/u.test(password) },
    { label: "Minimal 1 huruf kecil", met: /\p{Ll}/u.test(password) },
    { label: "Minimal 1 karakter spesial", met: /[^\p{L}\p{N}\s]/u.test(password) },
  ];
  const score = requirements.filter((requirement) => requirement.met).length;
  const labels = ["Belum diisi", "Lemah", "Cukup", "Baik", "Kuat"];

  return {
    requirements,
    score,
    label: labels[score],
    valid: score === requirements.length,
  };
}
