import { Check, X } from "lucide-react";
import { analyzePassword } from "../../lib/password";

export function PasswordStrength({ password }: { password: string }) {
  const strength = analyzePassword(password);

  return (
    <div className={`password-strength strength-${strength.score}`}>
      <div className="password-meter-row">
        <div
          aria-label="Kekuatan password"
          aria-valuemax={4}
          aria-valuemin={0}
          aria-valuenow={strength.score}
          className="password-meter"
          role="meter"
        >
          {strength.requirements.map((requirement) => (
            <span className={requirement.met ? "meter-segment met" : "meter-segment"} key={requirement.label} />
          ))}
        </div>
        <strong>{strength.label}</strong>
      </div>
      <div className="password-requirements">
        {strength.requirements.map((requirement) => (
          <span className={requirement.met ? "met" : ""} key={requirement.label}>
            {requirement.met ? <Check size={13} /> : <X size={13} />}
            {requirement.label}
          </span>
        ))}
      </div>
    </div>
  );
}
