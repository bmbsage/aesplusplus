#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct WavData {
    uint32_t sampleRate = 0;
    std::vector<double> samples;
};

uint32_t read_u32_le(std::istream &in) {
    uint8_t b[4] = {0, 0, 0, 0};
    in.read(reinterpret_cast<char *>(b), 4);
    return static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
           (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
}

uint16_t read_u16_le(std::istream &in) {
    uint8_t b[2] = {0, 0};
    in.read(reinterpret_cast<char *>(b), 2);
    return static_cast<uint16_t>(b[0]) | (static_cast<uint16_t>(b[1]) << 8);
}

bool read_wav_pcm16_mono(const std::string &path, WavData &out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }

    char riff[4] = {0};
    in.read(riff, 4);
    if (std::string(riff, 4) != "RIFF") {
        return false;
    }
    read_u32_le(in); // size
    char wave[4] = {0};
    in.read(wave, 4);
    if (std::string(wave, 4) != "WAVE") {
        return false;
    }

    uint16_t audioFormat = 0;
    uint16_t numChannels = 0;
    uint32_t sampleRate = 0;
    uint16_t bitsPerSample = 0;
    uint32_t dataSize = 0;
    std::streampos dataPos = 0;

    while (in && (!dataPos || !sampleRate)) {
        char chunkId[4] = {0};
        if (!in.read(chunkId, 4)) {
            break;
        }
        uint32_t chunkSize = read_u32_le(in);
        std::string id(chunkId, 4);
        if (id == "fmt ") {
            audioFormat = read_u16_le(in);
            numChannels = read_u16_le(in);
            sampleRate = read_u32_le(in);
            read_u32_le(in); // byte rate
            read_u16_le(in); // block align
            bitsPerSample = read_u16_le(in);
            if (chunkSize > 16) {
                in.seekg(chunkSize - 16, std::ios::cur);
            }
        } else if (id == "data") {
            dataPos = in.tellg();
            dataSize = chunkSize;
            in.seekg(chunkSize, std::ios::cur);
        } else {
            in.seekg(chunkSize, std::ios::cur);
        }
    }

    if (!dataPos || audioFormat != 1 || numChannels != 1 || bitsPerSample != 16) {
        return false;
    }

    in.clear();
    in.seekg(dataPos);
    size_t sampleCount = dataSize / 2;
    out.samples.resize(sampleCount);
    out.sampleRate = sampleRate;

    for (size_t i = 0; i < sampleCount; ++i) {
        int16_t s = static_cast<int16_t>(read_u16_le(in));
        out.samples[i] = static_cast<double>(s) / 32768.0;
    }

    return true;
}

std::vector<double> hamming_window(size_t n) {
    std::vector<double> w(n);
    if (n == 0) {
        return w;
    }
    const double denom = static_cast<double>(n - 1);
    for (size_t i = 0; i < n; ++i) {
        w[i] = 0.54 - 0.46 * std::cos((2.0 * M_PI * i) / denom);
    }
    return w;
}

std::vector<double> dft_power(const std::vector<double> &frame, size_t nfft) {
    std::vector<double> power(nfft / 2 + 1, 0.0);
    for (size_t k = 0; k <= nfft / 2; ++k) {
        double real = 0.0;
        double imag = 0.0;
        for (size_t n = 0; n < nfft; ++n) {
            double x = (n < frame.size()) ? frame[n] : 0.0;
            double angle = 2.0 * M_PI * static_cast<double>(k) * static_cast<double>(n) /
                           static_cast<double>(nfft);
            real += x * std::cos(angle);
            imag -= x * std::sin(angle);
        }
        power[k] = real * real + imag * imag;
    }
    return power;
}

double hz_to_mel(double hz) {
    return 2595.0 * std::log10(1.0 + hz / 700.0);
}

double mel_to_hz(double mel) {
    return 700.0 * (std::pow(10.0, mel / 2595.0) - 1.0);
}

std::vector<std::vector<double>> mel_filterbank(size_t nfft, uint32_t sampleRate,
                                                size_t numFilters) {
    size_t nfftBins = nfft / 2 + 1;
    double lowMel = hz_to_mel(0.0);
    double highMel = hz_to_mel(sampleRate / 2.0);

    std::vector<double> melPoints(numFilters + 2);
    for (size_t i = 0; i < melPoints.size(); ++i) {
        melPoints[i] = lowMel + (highMel - lowMel) * (static_cast<double>(i) /
                                                     static_cast<double>(numFilters + 1));
    }

    std::vector<size_t> binPoints(numFilters + 2);
    for (size_t i = 0; i < melPoints.size(); ++i) {
        double hz = mel_to_hz(melPoints[i]);
        size_t bin = static_cast<size_t>(std::floor((nfft + 1) * hz / sampleRate));
        if (bin >= nfftBins) {
            bin = nfftBins - 1;
        }
        binPoints[i] = bin;
    }

    std::vector<std::vector<double>> filters(numFilters, std::vector<double>(nfftBins, 0.0));
    for (size_t i = 0; i < numFilters; ++i) {
        size_t left = binPoints[i];
        size_t center = binPoints[i + 1];
        size_t right = binPoints[i + 2];

        for (size_t k = left; k < center; ++k) {
            if (center != left) {
                filters[i][k] = (static_cast<double>(k) - left) /
                                (static_cast<double>(center) - left);
            }
        }
        for (size_t k = center; k < right; ++k) {
            if (right != center) {
                filters[i][k] = (static_cast<double>(right) - k) /
                                (static_cast<double>(right) - center);
            }
        }
    }

    return filters;
}

std::vector<double> dct_type2(const std::vector<double> &vec, size_t numCoeffs) {
    std::vector<double> out(numCoeffs, 0.0);
    size_t n = vec.size();
    for (size_t k = 0; k < numCoeffs; ++k) {
        double sum = 0.0;
        for (size_t i = 0; i < n; ++i) {
            sum += vec[i] * std::cos(M_PI * static_cast<double>(k) *
                                     (static_cast<double>(i) + 0.5) /
                                     static_cast<double>(n));
        }
        out[k] = sum;
    }
    return out;
}

std::vector<double> compute_mfcc(const WavData &wav) {
    const uint32_t expectedRate = 16000;
    if (wav.sampleRate != expectedRate) {
        return {};
    }

    const size_t frameSize = static_cast<size_t>(expectedRate * 0.025); // 25 ms
    const size_t hopSize = static_cast<size_t>(expectedRate * 0.010);   // 10 ms
    const size_t nfft = 512;
    const size_t numFilters = 26;
    const size_t numCoeffs = 13;

    std::vector<double> window = hamming_window(frameSize);
    std::vector<std::vector<double>> filters = mel_filterbank(nfft, wav.sampleRate, numFilters);

    std::vector<double> mfccMean(numCoeffs, 0.0);
    size_t frameCount = 0;

    for (size_t start = 0; start + frameSize <= wav.samples.size(); start += hopSize) {
        std::vector<double> frame(frameSize);
        for (size_t i = 0; i < frameSize; ++i) {
            double sample = wav.samples[start + i];
            if (start + i > 0) {
                sample -= 0.97 * wav.samples[start + i - 1];
            }
            frame[i] = sample * window[i];
        }

        std::vector<double> power = dft_power(frame, nfft);
        std::vector<double> melEnergies(numFilters, 1e-9);

        for (size_t f = 0; f < numFilters; ++f) {
            double sum = 0.0;
            for (size_t k = 0; k < power.size(); ++k) {
                sum += power[k] * filters[f][k];
            }
            melEnergies[f] = std::log(sum + 1e-9);
        }

        std::vector<double> mfcc = dct_type2(melEnergies, numCoeffs);
        for (size_t i = 0; i < numCoeffs; ++i) {
            mfccMean[i] += mfcc[i];
        }
        ++frameCount;
    }

    if (frameCount == 0) {
        return {};
    }

    for (double &v : mfccMean) {
        v /= static_cast<double>(frameCount);
    }

    return mfccMean;
}

double cosine_similarity(const std::vector<double> &a, const std::vector<double> &b) {
    if (a.size() != b.size() || a.empty()) {
        return 0.0;
    }
    double dot = 0.0;
    double na = 0.0;
    double nb = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    if (na == 0.0 || nb == 0.0) {
        return 0.0;
    }
    return dot / (std::sqrt(na) * std::sqrt(nb));
}

bool save_profile(const std::string &path, const std::vector<double> &vec) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        return false;
    }
    out << vec.size() << "\n";
    for (double v : vec) {
        out << v << "\n";
    }
    return true;
}

bool load_profile(const std::string &path, std::vector<double> &vec) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    size_t n = 0;
    in >> n;
    if (n == 0) {
        return false;
    }
    vec.resize(n);
    for (size_t i = 0; i < n; ++i) {
        in >> vec[i];
    }
    return true;
}

void print_usage() {
    std::cout << "Usage:\n";
    std::cout << "  voice_verify_demo enroll <input.wav> <profile.txt>\n";
    std::cout << "  voice_verify_demo verify <profile.txt> <input.wav>\n";
    std::cout << "Notes:\n";
    std::cout << "  - WAV must be 16-bit PCM mono at 16 kHz.\n";
    std::cout << "  - This is a simple baseline (MFCC + cosine similarity).\n";
}

} // namespace

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "enroll") {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        std::string wavPath = argv[2];
        std::string profilePath = argv[3];

        WavData wav;
        if (!read_wav_pcm16_mono(wavPath, wav)) {
            std::cerr << "Failed to read WAV file." << std::endl;
            return 1;
        }

        std::vector<double> mfcc = compute_mfcc(wav);
        if (mfcc.empty()) {
            std::cerr << "MFCC extraction failed. Ensure 16 kHz mono WAV." << std::endl;
            return 1;
        }

        if (!save_profile(profilePath, mfcc)) {
            std::cerr << "Failed to save profile." << std::endl;
            return 1;
        }

        std::cout << "Enrollment complete. Saved profile to " << profilePath << std::endl;
        return 0;
    }

    if (mode == "verify") {
        if (argc != 4) {
            print_usage();
            return 1;
        }
        std::string profilePath = argv[2];
        std::string wavPath = argv[3];

        std::vector<double> profile;
        if (!load_profile(profilePath, profile)) {
            std::cerr << "Failed to load profile." << std::endl;
            return 1;
        }

        WavData wav;
        if (!read_wav_pcm16_mono(wavPath, wav)) {
            std::cerr << "Failed to read WAV file." << std::endl;
            return 1;
        }

        std::vector<double> mfcc = compute_mfcc(wav);
        if (mfcc.empty()) {
            std::cerr << "MFCC extraction failed. Ensure 16 kHz mono WAV." << std::endl;
            return 1;
        }

        double score = cosine_similarity(profile, mfcc);
        double threshold = 0.75; // Tune with your own data.

        std::cout << "Similarity score: " << score << std::endl;
        if (score >= threshold) {
            std::cout << "Result: match" << std::endl;
        } else {
            std::cout << "Result: no match" << std::endl;
        }
        return 0;
    }

    print_usage();
    return 1;
}
