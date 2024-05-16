"use client"

import { useCallback, useEffect, useState } from "react";
import { HashLoader } from "react-spinners"
import { useSearchParams } from "next/navigation";

import { newVerification } from "@/actions/new-verification";
import CardWrapper from "./card-wrapper";
import { FormError } from "../form-error";
import { FormSuccess } from "../form-success";


const NewVerificationForm = () => {
    const [error, setError] = useState<string | undefined>();
    const [success, setSuccess] = useState<string | undefined>();

    const searchParams = useSearchParams();
    const token = searchParams.get("token");

    const onSubmit = useCallback(() => {
        if (success || error) return;

        if (!token) {
            setError("Missing token!");
            return
        }

        newVerification(token)
            .then((data) => {
                setSuccess(data.success);
                setError(data.error);
            })
            .catch(() => {
                setError("Something went wrong!");
            })
    }, [token, success, error]);

    useEffect(() => {
        onSubmit();
    }, [onSubmit]);
    return (
        <CardWrapper
            headerLabel="Verifying your email!"
            backButtonLabel="Back to login"
            backButtonHref="/auth/login"
        >
            <div className="flex items-center justify-center w-full">
                {
                    !success && !error && <HashLoader />
                }
                <FormSuccess message={success} />
                {!success && (
                    <FormError message={error} />
                )}
            </div>
        </CardWrapper>
    );
}

export default NewVerificationForm;