package org.wso2.carbon.identity.openid4vc.presentation.authenticator.model;

import com.google.gson.annotations.SerializedName;

import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Model class representing a Verifiable Presentation Submission.
 * This stores the VP token submitted by the wallet for transient handoff to the poller.
 */
public class VPSubmission implements Serializable {

    /**
     * Serial version UID.
     */
    private static final long serialVersionUID = 1L;

    /**
     * Transient storage mapping requestId to submission.
     */
    private static final Map<String, VPSubmission> submissions = new ConcurrentHashMap<>();

    /**
     * The ID of the request this submission belongs to.
     */
    @SerializedName("state")
    private String requestId;

    /**
     * The VP token string submitted by the wallet.
     */
    @SerializedName("vp_token")
    private String vpToken;

    /**
     * The presentation submission JSON string.
     */
    @SerializedName("presentation_submission")
    private String presentationSubmission;

    /**
     * Default constructor for VPSubmission.
     */
    public VPSubmission() {

    }

    /**
     * Store a submission for transient handoff.
     *
     * @param submission The submission to store.
     */
    public static void store(VPSubmission submission) {

        if (submission != null && submission.getRequestId() != null) {
            submissions.put(submission.getRequestId(), submission);
        }
    }

    /**
     * Retrieve and remove a submission for a request.
     *
     * @param requestId The request ID.
     * @return The submission, or null if not found.
     */
    public static VPSubmission consume(String requestId) {

        if (requestId == null) {
            return null;
        }
        return submissions.remove(requestId);
    }

    /**
     * Constructor for VPSubmission using the Builder pattern.
     *
     * @param builder The VPSubmission builder.
     */
    private VPSubmission(Builder builder) {

        this.requestId = builder.requestId;
        this.vpToken = builder.vpToken;
        this.presentationSubmission = builder.presentationSubmission;
    }

    /**
     * Get the request ID associated with this submission.
     *
     * @return The request ID string.
     */
    public String getRequestId() {

        return requestId;
    }

    /**
     * Set the request ID associated with this submission.
     *
     * @param requestId The request ID string.
     */
    public void setRequestId(String requestId) {

        this.requestId = requestId;
    }

    /**
     * Get the VP token string.
     *
     * @return The VP token string.
     */
    public String getVpToken() {

        return vpToken;
    }

    /**
     * Set the VP token string.
     *
     * @param vpToken The VP token string.
     */
    public void setVpToken(String vpToken) {

        this.vpToken = vpToken;
    }

    /**
     * Get the presentation submission JSON.
     *
     * @return The presentation submission JSON string.
     */
    public String getPresentationSubmission() {

        return presentationSubmission;
    }

    /**
     * Set the presentation submission JSON.
     *
     * @param presentationSubmission The presentation submission JSON string.
     */
    public void setPresentationSubmission(String presentationSubmission) {

        this.presentationSubmission = presentationSubmission;
    }

    /**
     * Builder class for generating VPSubmission instances.
     */
    public static class Builder {

        /**
         * The ID of the request this submission belongs to.
         */
        @SerializedName("state")
        private String requestId;

        /**
         * The VP token string submitted by the wallet.
         */
        @SerializedName("vp_token")
        private String vpToken;

        /**
         * The presentation submission JSON string.
         */
        @SerializedName("presentation_submission")
        private String presentationSubmission;

        /**
         * Set the request ID.
         *
         * @param requestId The request identifier.
         * @return The builder instance.
         */
        public Builder requestId(String requestId) {

            this.requestId = requestId;
            return this;
        }

        /**
         * Set the VP token.
         *
         * @param vpToken The VP token string.
         * @return The builder instance.
         */
        public Builder vpToken(String vpToken) {

            this.vpToken = vpToken;
            return this;
        }

        /**
         * Set the presentation submission JSON.
         *
         * @param presentationSubmission The presentation submission string.
         * @return The builder instance.
         */
        public Builder presentationSubmission(String presentationSubmission) {

            this.presentationSubmission = presentationSubmission;
            return this;
        }

        /**
         * Create the VPSubmission instance.
         *
         * @return A new VPSubmission object.
         */
        public VPSubmission build() {

            return new VPSubmission(this);
        }
    }

    @Override
    public String toString() {

        return "VPSubmission{" +
                "requestId='" + requestId + '\'' +
                ", hasVpToken=" + (vpToken != null && !vpToken.isEmpty()) +
                ", hasPresentationSubmission=" + (presentationSubmission != null && !presentationSubmission.isEmpty()) +
                '}';
    }
}
